//! The HTTP side: hands each request to the [`Agent`] and sends back its reply.

use std::future::Future;
use std::io;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{Request as HttpRequest, State};
use axum::http::Response;
use tokio::net::TcpListener;

use crate::service::{Agent, Reply, Request};

/// Requests with a larger body are not read; they get the plain 404.
pub const MAX_BODY: usize = 1 << 20;

/// The clock in Unix seconds.
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// The one-minute load average from the text of `/proc/loadavg`.
pub fn parse_loadavg(text: &str) -> Option<f64> {
    text.split_whitespace()
        .next()?
        .parse::<f64>()
        .ok()
        .filter(|load| load.is_finite())
}

/// This machine's one-minute load average, if the system tells it.
fn read_load1() -> Option<f64> {
    std::fs::read_to_string("/proc/loadavg")
        .ok()
        .and_then(|text| parse_loadavg(&text))
}

/// How long a client may take to send a request body before it is cut off. (Slow request
/// headers are the reverse proxy's job: Caddy sits in front of the agent.)
pub const BODY_TIMEOUT: Duration = Duration::from_secs(10);

/// What the handler needs besides the request.
struct Shared {
    agent: Arc<Agent>,
    body_timeout: Duration,
}

pub fn router(agent: Arc<Agent>, body_timeout: Duration) -> Router {
    // One handler takes every request, so a wrong path and a missing signature can
    // only ever look the same.
    Router::new().fallback(handle).with_state(Arc::new(Shared {
        agent,
        body_timeout,
    }))
}

/// Serves the agent on `listener` until `shutdown` completes.
pub async fn serve(
    listener: TcpListener,
    agent: Arc<Agent>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> io::Result<()> {
    serve_with(listener, agent, BODY_TIMEOUT, shutdown).await
}

/// Like [`serve`], with the body timeout chosen by the caller (the tests use a short one).
pub async fn serve_with(
    listener: TcpListener,
    agent: Arc<Agent>,
    body_timeout: Duration,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> io::Result<()> {
    axum::serve(listener, router(agent, body_timeout))
        .with_graceful_shutdown(shutdown)
        .await
}

async fn handle(State(shared): State<Arc<Shared>>, request: HttpRequest) -> Response<Body> {
    let (head, body) = request.into_parts();
    // A body that is too big, broken or too slow is never read to the end.
    let Ok(Ok(body)) = tokio::time::timeout(shared.body_timeout, to_bytes(body, MAX_BODY)).await
    else {
        return respond(Reply::not_found());
    };
    let agent = shared.agent.clone();
    let header = |name: &str| {
        head.headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    };
    let (time, nonce, signature) = (
        header("x-bf-time"),
        header("x-bf-nonce"),
        header("x-bf-sig"),
    );
    let method = head.method.as_str().to_owned();
    let path = head
        .uri
        .path_and_query()
        .map_or_else(|| "/".to_owned(), |p| p.as_str().to_owned());
    // The agent talks to `wg` and the disk, which block: keep that off the async threads.
    let reply = tokio::task::spawn_blocking(move || {
        let request = Request {
            method: &method,
            path_and_query: &path,
            time: time.as_deref(),
            nonce: nonce.as_deref(),
            signature: signature.as_deref(),
            body: &body,
        };
        // The agent reads the clock itself, after it holds its verifier lock.
        agent.handle_with(unix_now, read_load1(), &request)
    })
    .await
    .unwrap_or_else(|_| Reply {
        status: 500,
        body: String::new(),
    });
    respond(reply)
}

fn respond(reply: Reply) -> Response<Body> {
    let mut builder = Response::builder().status(reply.status);
    if !reply.body.is_empty() {
        builder = builder.header("content-type", "application/json");
    }
    builder
        .body(Body::from(reply.body))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpStream};
    use std::thread::JoinHandle;

    use bf_common::sign::{Parts, unhex};
    use serde_json::{Value, json};
    use tokio::sync::oneshot;

    use super::*;
    use crate::client;
    use crate::store::Store;
    use crate::testutil::{FakeWg, K1, K2, TempDir};

    const SECRET_HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    fn secret() -> Vec<u8> {
        unhex(SECRET_HEX).unwrap()
    }

    /// A real agent on a real localhost socket, over a fake WireGuard.
    struct Server {
        addr: SocketAddr,
        wg: Arc<FakeWg>,
        stop: Option<oneshot::Sender<()>>,
        thread: Option<JoinHandle<()>>,
        _dir: TempDir,
    }

    impl Server {
        fn start(wg: FakeWg) -> Server {
            Server::start_with(wg, BODY_TIMEOUT)
        }

        fn start_with(wg: FakeWg, body_timeout: Duration) -> Server {
            let dir = TempDir::new("server");
            let wg = Arc::new(wg);
            let store = Store::new(dir.path().join("state"));
            let agent = Arc::new(Agent::new(wg.clone(), store, secret(), 180));
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let addr = listener.local_addr().unwrap();
            let (stop, stopped) = oneshot::channel::<()>();
            let thread = std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(async move {
                    let listener = TcpListener::from_std(listener).unwrap();
                    serve_with(listener, agent, body_timeout, async {
                        let _ = stopped.await;
                    })
                    .await
                    .unwrap();
                });
            });
            Server {
                addr,
                wg,
                stop: Some(stop),
                thread: Some(thread),
                _dir: dir,
            }
        }

        fn call(&self, method: &str, path: &str, body: &[u8]) -> io::Result<(u16, String)> {
            let nonce = client::random_nonce()?;
            let parts = Parts {
                method,
                path_and_query: path,
                time: unix_now(),
                nonce: &nonce,
                body,
            };
            client::request(self.addr, &secret(), &parts)
        }

        /// Sends the text as it is and returns everything the server wrote back.
        fn raw(&self, text: &str) -> String {
            let mut stream = TcpStream::connect(self.addr).unwrap();
            stream.write_all(text.as_bytes()).unwrap();
            let mut answer = String::new();
            stream.read_to_string(&mut answer).unwrap();
            answer
        }
    }

    impl Drop for Server {
        fn drop(&mut self) {
            if let Some(stop) = self.stop.take() {
                let _ = stop.send(());
            }
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    #[test]
    fn a_signed_status_request_over_a_real_socket_is_answered() {
        let server = Server::start(FakeWg::with_peers(&[(K1, &["10.66.1.2/32"])]));

        let (status, body) = server.call("GET", "/v1/status", b"").unwrap();

        assert_eq!(status, 200, "{body}");
        let body: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(body["peers_total"], json!(1));
        assert_eq!(body["interface"]["listen_port"], json!(51820));
    }

    #[test]
    fn a_list_sent_over_the_socket_is_applied() {
        let server = Server::start(FakeWg::with_peers(&[(K2, &["10.66.1.3/32"])]));
        let list = json!({ "version": 3, "peers": [{ "public_key": K1, "allowed_ips": ["10.77.0.5/32"] }] });

        let (status, body) = server
            .call("PUT", "/v1/peers", list.to_string().as_bytes())
            .unwrap();

        assert_eq!(status, 200, "{body}");
        assert_eq!(
            serde_json::from_str::<Value>(&body).unwrap()["added"],
            json!(1)
        );
        assert_eq!(
            server.wg.peers(),
            [(K1.to_string(), vec!["10.77.0.5/32".to_string()])]
        );
    }

    #[test]
    fn an_unsigned_request_gets_the_same_empty_404_as_a_path_that_does_not_exist() {
        let server = Server::start(FakeWg::default());
        let ask = |path: &str| {
            server.raw(&format!(
                "GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
            ))
        };
        let without_date = |answer: String| {
            answer
                .lines()
                .filter(|line| !line.to_lowercase().starts_with("date:"))
                .collect::<Vec<_>>()
                .join("\n")
        };

        let real_path = ask("/v1/status");
        let no_such_path = ask("/nope");

        assert!(real_path.starts_with("HTTP/1.1 404"), "{real_path}");
        assert!(
            real_path.ends_with("\r\n\r\n"),
            "no body expected: {real_path:?}"
        );
        assert_eq!(without_date(real_path), without_date(no_such_path));
    }

    #[test]
    fn a_body_over_the_limit_is_never_applied() {
        let server = Server::start(FakeWg::default());
        let huge = vec![b' '; MAX_BODY + 1];

        let outcome = server.call("PUT", "/v1/peers", &huge);

        // The server may answer 404 or hang up while the body is still being sent.
        match outcome {
            Ok((status, _)) => assert_eq!(status, 404),
            Err(e) => assert!(
                matches!(
                    e.kind(),
                    io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
                ),
                "{e:?}"
            ),
        }
        assert!(server.wg.calls().is_empty());
    }

    #[test]
    fn a_client_that_stalls_in_the_middle_of_its_body_is_cut_off() {
        let server = Server::start_with(FakeWg::default(), Duration::from_millis(300));
        let mut stream = TcpStream::connect(server.addr).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        // Promises 100 bytes of body, sends 5 and goes quiet.
        stream
            .write_all(
                b"PUT /v1/peers HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Length: 100\r\n\r\nhello",
            )
            .unwrap();

        let mut answer = String::new();
        let outcome = stream.read_to_string(&mut answer);

        assert!(
            outcome.is_ok(),
            "the server should answer and close: {outcome:?}"
        );
        assert!(answer.starts_with("HTTP/1.1 404"), "{answer}");
    }

    #[test]
    fn the_load_average_is_the_first_number_in_proc_loadavg() {
        assert_eq!(parse_loadavg("0.12 0.30 0.25 1/123 4567\n"), Some(0.12));
        assert_eq!(parse_loadavg(""), None);
        assert_eq!(parse_loadavg("busy 0.30"), None);
        assert_eq!(parse_loadavg("NaN 0.30"), None);
    }
}

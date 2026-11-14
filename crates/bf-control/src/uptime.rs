//! The status page's uptime history: hourly counts of the passes in which a server was
//! working or down, kept in the database so it survives a restart (`specs/status-history.md`).
//!
//! Only the poller writes it (`Store::record_uptime`, after each pass) and only the board's
//! summary reaches the web layer, so the public pages never touch the database.

use rusqlite::TransactionBehavior;

use crate::store::{Store, StoreError, from_sql, to_sql};

/// Rows older than this many days are deleted.
pub const KEEP_DAYS: u64 = 90;
/// The percentage is worked out over this many days.
pub const WINDOW_DAYS: u64 = 30;

/// What one pass said about one server. A server being fixed, or one nobody has a reading
/// for, says nothing and is not recorded at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Availability {
    /// Some agent of the server was online (its word was Up or Overloaded).
    Working,
    /// Every agent that is not switched off failed (its word was Down).
    Down,
}

/// One server's counts over the window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Uptime {
    pub title: String,
    pub place: String,
    /// Passes in which it was working.
    pub up: u64,
    /// Passes in which it was down.
    pub down: u64,
    /// The first hour (Unix seconds / 3600) with a count in the window.
    pub first_hour: u64,
}

/// Up over up plus down, in tenths of a percent, **rounded down** so a real outage never
/// reads as 100.0: 1000 only when nothing was down. `None` when nothing was counted.
pub fn tenths(up: u64, down: u64) -> Option<u16> {
    let total = u128::from(up) + u128::from(down);
    if total == 0 {
        return None;
    }
    if down == 0 {
        return Some(1000);
    }
    // Any down time keeps it under 100.0, whatever the rounding.
    let floor = u128::from(up) * 1000 / total;
    Some(floor.min(999) as u16)
}

impl Store {
    /// Adds one pass's result for each server to the current hour's row (a new row if there is
    /// none), in one transaction.
    pub fn record_uptime(
        &mut self,
        now: u64,
        passes: &[(String, String, Availability)],
    ) -> Result<(), StoreError> {
        if passes.is_empty() {
            return Ok(());
        }
        let hour = to_sql(now / 3600);
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        {
            let mut add = tx.prepare(
                "INSERT INTO uptime_hours (title, place, hour, up, down)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT (title, place, hour)
                 DO UPDATE SET up = up + excluded.up, down = down + excluded.down",
            )?;
            for (title, place, what) in passes {
                let (up, down) = match what {
                    Availability::Working => (1, 0),
                    Availability::Down => (0, 1),
                };
                add.execute(rusqlite::params![title, place, hour, up, down])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Deletes the rows older than [`KEEP_DAYS`]. Gives how many went.
    pub fn prune_uptime(&mut self, now: u64) -> Result<usize, StoreError> {
        let oldest_kept = (now / 3600).saturating_sub(KEEP_DAYS * 24);
        Ok(self.conn.execute(
            "DELETE FROM uptime_hours WHERE hour < ?1",
            [to_sql(oldest_kept)],
        )?)
    }

    /// Each server's counts over the last [`WINDOW_DAYS`] days, by title and then place;
    /// a server with no counted pass in the window is left out.
    pub fn uptime_summary(&self, now: u64) -> Result<Vec<Uptime>, StoreError> {
        let now_hour = now / 3600;
        let first = now_hour.saturating_sub(WINDOW_DAYS * 24 - 1);
        let mut query = self.conn.prepare(
            "SELECT title, place, SUM(up), SUM(down), MIN(hour)
             FROM uptime_hours WHERE hour >= ?1 AND hour <= ?2
             GROUP BY title, place HAVING SUM(up) + SUM(down) > 0
             ORDER BY title, place",
        )?;
        let rows = query.query_map([to_sql(first), to_sql(now_hour)], |row| {
            Ok(Uptime {
                title: row.get(0)?,
                place: row.get(1)?,
                up: from_sql(row.get(2)?),
                down: from_sql(row.get(3)?),
                first_hour: from_sql(row.get(4)?),
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR: u64 = 3600;
    const T: u64 = 1_800_000_000;

    fn pass(title: &str, place: &str, what: Availability) -> (String, String, Availability) {
        (title.to_string(), place.to_string(), what)
    }

    fn rows(store: &Store) -> Vec<(String, String, u64, u64, u64)> {
        let mut q = store
            .conn
            .prepare(
                "SELECT title, place, hour, up, down FROM uptime_hours ORDER BY title, place, hour",
            )
            .unwrap();
        q.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)? as u64,
                r.get::<_, i64>(3)? as u64,
                r.get::<_, i64>(4)? as u64,
            ))
        })
        .unwrap()
        .map(Result::unwrap)
        .collect()
    }

    fn put(store: &Store, title: &str, hour: u64, up: u64, down: u64) {
        store
            .conn
            .execute(
                "INSERT INTO uptime_hours (title, place, hour, up, down) VALUES (?1, 'Canada', ?2, ?3, ?4)",
                rusqlite::params![title, hour as i64, up as i64, down as i64],
            )
            .unwrap();
    }

    #[test]
    fn a_pass_adds_to_the_current_hours_row_and_a_new_hour_is_a_new_row() {
        let mut store = Store::open_in_memory().unwrap();
        let toronto = |a| pass("Toronto", "Canada", a);
        store
            .record_uptime(T, &[toronto(Availability::Working)])
            .unwrap();
        store
            .record_uptime(T + 10, &[toronto(Availability::Working)])
            .unwrap();
        store
            .record_uptime(T + 20, &[toronto(Availability::Down)])
            .unwrap();
        let hour = T / HOUR;
        assert_eq!(
            rows(&store),
            [("Toronto".to_string(), "Canada".to_string(), hour, 2, 1)]
        );
        store
            .record_uptime(T + HOUR, &[toronto(Availability::Working)])
            .unwrap();
        assert_eq!(rows(&store).len(), 2);
        assert_eq!(rows(&store)[1].2, hour + 1);
    }

    #[test]
    fn each_server_has_its_own_row_by_title_and_by_place() {
        let mut store = Store::open_in_memory().unwrap();
        store
            .record_uptime(
                T,
                &[
                    pass("Toronto", "Canada", Availability::Working),
                    pass("Dallas", "United States", Availability::Down),
                    pass("Toronto", "France", Availability::Working),
                ],
            )
            .unwrap();
        assert_eq!(rows(&store).len(), 3);
        store.record_uptime(T + 1, &[]).unwrap();
        assert_eq!(rows(&store).len(), 3, "nothing to record changes nothing");
    }

    #[test]
    fn the_summary_adds_up_the_last_30_days_and_leaves_older_hours_out() {
        let store = Store::open_in_memory().unwrap();
        let now_hour = T / HOUR;
        let window_start = now_hour - (WINDOW_DAYS * 24 - 1);
        put(&store, "Toronto", window_start - 1, 1000, 0); // one hour too old
        put(&store, "Toronto", window_start, 10, 1); // the first hour inside
        put(&store, "Toronto", now_hour, 5, 0); // the current hour
        put(&store, "Toronto", now_hour + 1, 99, 99); // the future: not counted
        let all = store.uptime_summary(T).unwrap();
        assert_eq!(
            all,
            [Uptime {
                title: "Toronto".to_string(),
                place: "Canada".to_string(),
                up: 15,
                down: 1,
                first_hour: window_start,
            }]
        );
    }

    #[test]
    fn the_summary_is_ordered_and_leaves_out_a_server_with_nothing_counted() {
        let store = Store::open_in_memory().unwrap();
        let h = T / HOUR;
        put(&store, "Toronto", h, 1, 0);
        put(&store, "Dallas", h, 0, 1);
        put(&store, "Empty", h, 0, 0);
        let names: Vec<_> = store
            .uptime_summary(T)
            .unwrap()
            .into_iter()
            .map(|u| u.title)
            .collect();
        assert_eq!(names, ["Dallas", "Toronto"]);
    }

    #[test]
    fn rows_older_than_90_days_are_deleted_and_the_boundary_hour_stays() {
        let mut store = Store::open_in_memory().unwrap();
        let h = T / HOUR;
        let oldest_kept = h - KEEP_DAYS * 24;
        put(&store, "Toronto", oldest_kept - 1, 1, 0);
        put(&store, "Toronto", oldest_kept, 1, 0);
        put(&store, "Toronto", h, 1, 0);
        assert_eq!(store.prune_uptime(T).unwrap(), 1);
        let hours: Vec<u64> = rows(&store).into_iter().map(|r| r.2).collect();
        assert_eq!(hours, [oldest_kept, h]);
        assert_eq!(store.prune_uptime(T).unwrap(), 0, "twice is fine");
    }

    #[test]
    fn the_windows_are_the_ones_the_page_and_the_docs_promise() {
        assert_eq!(WINDOW_DAYS, 30, "the page says the last 30 days");
        assert_eq!(KEEP_DAYS, 90, "the docs say rows are kept 90 days");
        const { assert!(KEEP_DAYS >= WINDOW_DAYS, "the history outlives the window") };
    }

    #[test]
    fn the_percentage_is_up_over_total_in_tenths_rounded_down() {
        assert_eq!(tenths(0, 0), None, "nothing counted");
        assert_eq!(tenths(1, 0), Some(1000));
        assert_eq!(tenths(500, 0), Some(1000));
        assert_eq!(tenths(0, 5), Some(0));
        assert_eq!(tenths(1, 1), Some(500));
        assert_eq!(tenths(3, 1), Some(750));
        assert_eq!(tenths(998, 2), Some(998), "99.8");
        assert_eq!(tenths(9996, 4), Some(999), "99.96 reads 99.9, never 100.0");
        assert_eq!(
            tenths(99_999, 1),
            Some(999),
            "any down time keeps it under 100.0"
        );
        assert_eq!(tenths(u64::MAX, 1), Some(999), "no overflow");
    }

    #[test]
    fn the_percentage_never_rounds_up_and_only_zero_down_time_reads_100() {
        for up in 0..=300u64 {
            for down in 0..=40u64 {
                let Some(t) = tenths(up, down) else {
                    assert_eq!(up + down, 0);
                    continue;
                };
                assert!(u64::from(t) * (up + down) <= up * 1000, "{up}/{down}: {t}");
                assert_eq!(t == 1000, down == 0, "{up}/{down}: {t}");
            }
        }
    }
}

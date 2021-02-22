use std::time::Instant;

use tokio::time::Duration;

use hyper::StatusCode;
use hyper::Client;

use crate::results::WorkerResult;
use crate::utils::get_request;



/// A single http/1 connection worker
///
/// Builds a new http client with the http2_only option set either to false.
///
/// It then waits for the signaller to start sending pings to queue requests,
/// a client can take a request from the queue and then send the request,
/// these times are then measured and compared against previous latencies
/// to work out the min, max, total time and total requests of the given
/// worker which can then be sent back to the controller when the handle
/// is awaited.
///
/// todo Make concurrent handling for h2 tests
pub async fn client(
    time_for: Duration,
    host: String,
    predicted_size: usize,
) -> Result<WorkerResult, String> {
    let session = Client::builder()
        .http2_only(true)
        .build_http();

    let mut times: Vec<Duration> = Vec::with_capacity(predicted_size);
    let mut buffer_counter: usize = 0;

    let start = Instant::now();
    while time_for > start.elapsed() {
        let req = get_request(&host);

        let ts = Instant::now();
        let re = session.request(req).await;
        let took = ts.elapsed();

        if let Err(e) = &re {
            return Err(format!("{:?}", e));
        } else if let Ok(r) = re {
            let status = r.status();
            assert_eq!(status, StatusCode::OK);

            let buff = match hyper::body::to_bytes(r).await {
                Ok(buff) => buff,
                Err(e) => return Err(format!(
                    "Failed to read stream {:?}",
                     e
                ))
            };
            buffer_counter += buff.len();
        }

        times.push(took);

    }
    let time_taken = start.elapsed();

    let result = WorkerResult{
        total_times: vec![time_taken],
        request_times: times,
        buffer_sizes: vec![buffer_counter]
    };

    Ok(result)
}

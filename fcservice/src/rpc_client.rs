//! Fcservice RPC Client

use jsonrpc_core_client::TypedClient;
use jsonrpc_core_client::RpcChannel;
use jsonrpc_core_client::RpcError;
use futures::Future;

#[derive(Clone)]
struct TestClient(TypedClient);

impl From<RpcChannel> for TestClient {
    fn from(channel: RpcChannel) -> Self {
        TestClient(channel.into())
    }
}

impl TestClient {
    async fn hello(&self, msg: &'static str) -> Result<String, RpcError> {
        // Fix this
        self.0.call_method("hello", "String", (msg, )).wait()
    }
    //    fn hello(&self, msg: &'static str) -> impl Future<Item=String, Error=RpcError> {
//        self.0.call_method("hello", "String", (msg, ))
//    }
    fn fail(&self) -> impl Future<Item=(), Error=RpcError> {
        self.0.call_method("fail", "()", ())
    }
    fn notify(&self, value: u64) -> impl Future<Item=(), Error=RpcError> {
        self.0.notify("notify", (value, ))
    }
}

pub fn start(url: &str) {
    // TODO: enable and fix this
//    let run = jsonrpc_core_client::transports::http::connect(url)
//        .and_then(|client: TestClient| {
//            async {
//                let result = client.hello("http").await;
//                drop(client);
//                println!("{:?}", result);
//            }
//        }).map_err(|e| {});
//    run.wait();
}

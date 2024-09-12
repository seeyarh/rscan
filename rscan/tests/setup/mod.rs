use afpacket::sync::RawPacketStream;
use std::sync::Once;

static INIT: Once = Once::new();

fn setup_logging() {
    INIT.call_once(|| {
        env_logger::init();
    });
}

mod veth_setup;

pub fn run_test<F>(test: F)
where
    F: Fn(RawPacketStream, RawPacketStream) + Send + 'static,
{
    setup_logging();
    let inner = move |dev1_if_name: String, dev2_if_name: String| {
        let mut p1 = RawPacketStream::new().expect("failed to create raw packet stream");
        p1.bind(&dev1_if_name).expect("failed to bind");

        let mut p2 = RawPacketStream::new().expect("failed to create raw packet stream");
        p2.bind(&dev2_if_name).expect("failed to bind");

        test(p1, p2)
    };

    veth_setup::run_with_dev(inner);
}

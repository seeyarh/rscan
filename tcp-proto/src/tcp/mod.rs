#[derive(Debug, PartialEq, Clone)]
enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

#[derive(Debug)]
enum TcpEvent {
    PassiveOpen,
    ActiveOpen,
    Send,
    ReceiveSyn,
    ReceiveAck,
    Close,
    Timeout,
    ReceiveFin,
}

struct TcpConnection {
    state: TcpState,
}

impl TcpConnection {
    fn new() -> Self {
        TcpConnection {
            state: TcpState::Closed,
        }
    }

    fn handle_event(&mut self, event: TcpEvent) {
        use TcpEvent::*;
        use TcpState::*;

        self.state = match (&self.state, event) {
            (Closed, PassiveOpen) => Listen,
            (Closed, ActiveOpen) => SynSent,
            (Listen, ReceiveSyn) => SynReceived,
            (SynSent, ReceiveSyn) => SynReceived,
            (SynSent, ReceiveAck) => Established,
            (SynReceived, ReceiveAck) => Established,
            (Established, Close) => FinWait1,
            (Established, ReceiveFin) => CloseWait,
            (FinWait1, ReceiveAck) => FinWait2,
            (FinWait2, ReceiveFin) => TimeWait,
            (CloseWait, Close) => LastAck,
            (LastAck, ReceiveAck) => Closed,
            (TimeWait, Timeout) => Closed,
            (Closing, ReceiveAck) => TimeWait,
            _ => self.state.clone(), // No valid transition
        };
    }

    fn get_state(&self) -> &TcpState {
        &self.state
    }
}

use crate::arch::x86_64::{cpu, smp};
use crate::{exit, ktest, time};

fn t_kdump_ap_park() -> bool {
    if let Err(error) = smp::bringup() {
        crate::log_fatal!("kdump-ap-probe: AP 没起来 {:?}", error);
        return false;
    }
    let wanted = cpu::registered();
    let start = time::tsc::now();
    while cpu::online_count() < wanted && time::tsc::now().wrapping_sub(start) < 100_000_000 {
        core::hint::spin_loop();
    }
    let online = cpu::online_count();
    crate::log_info!("kdump-ap-probe: online={}/{}，随后进入致命捕获", online, wanted);
    if online != wanted {
        return false;
    }
    exit::finish(exit::Code::ExceptionFatal)
}

ktest!(KT_KDUMP_AP_PARK, t_kdump_ap_park);

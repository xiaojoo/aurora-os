use crate::{ktest, security::rand};

fn t_csprng_contract() -> bool {
    let mut key = [0u32; 8];
    for (i, word) in key.iter_mut().enumerate() {
        *word = u32::from_le_bytes([(i * 4) as u8, (i * 4 + 1) as u8, (i * 4 + 2) as u8, (i * 4 + 3) as u8]);
    }
    let block = rand::block(&key, 1);
    let mut changed_key = key;
    changed_key[0] ^= 1;
    let block_ok = block != rand::block(&changed_key, 1) && block != rand::block(&key, 2);

    let sources = rand::sources();
    let seeded = rand::is_seeded();
    let mut first = [0u8; 128];
    let mut second = [0u8; 128];
    let first_result = rand::fill(&mut first);
    let second_result = rand::fill(&mut second);
    let fill_ok = if sources >= rand::MIN_SOURCES {
        seeded && first_result.is_ok() && second_result.is_ok() && first != second
            && first.iter().any(|&b| b != 0)
    } else {
        !seeded && matches!(first_result, Err(rand::RandError::NotSeeded))
            && matches!(second_result, Err(rand::RandError::NotSeeded))
    };

    crate::log_info!(
        "csprng: block ctr=1 {:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x}",
        block[0], block[1], block[2], block[3], block[4], block[5], block[6], block[7],
        block[8], block[9], block[10], block[11], block[12], block[13], block[14], block[15]
    );
    crate::log_info!(
        "csprng: 判据 sources={} seeded={} block={} fill={}",
        sources, seeded, block_ok, fill_ok
    );
    block_ok && fill_ok
}
ktest!(KT_CSPRNG_CONTRACT, t_csprng_contract);

#[cfg(feature = "fault-rand-reentrant")]
fn t_rand_reentry_must_escalate() -> bool {
    crate::log_warn!("fault-rand-reentrant: 按设计重复获取随机数锁");
    rand::reenter_for_test();
    false
}
#[cfg(feature = "fault-rand-reentrant")]
ktest!(KT_RAND_REENTRY, t_rand_reentry_must_escalate);

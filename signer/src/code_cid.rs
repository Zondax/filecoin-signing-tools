use lazy_static::lazy_static;
use serde_json::{json, Value};

lazy_static! {
    pub static ref ACTOR_CODE_CIDS: Value = json!(
    {
        "init": {
            "butterflynet": "bafk2bzaceahxin3sf5f6ude5j6we4yeqlg66s5qe4tu7lwp26jcg7yp2ns6hi",
            "calibrationnet": "bafk2bzaceadyfilb22bcvzvnpzbg2lyg6npmperyq6es2brvzjdh5rmywc4ry",
            "caterpillarnet": "bafk2bzacedajw5ptnwfdidv6m4rvd4c2m7dve4lhfbawygl5idkalcxbiiudu",
            "devnet": "bafk2bzacedarbnovmucppbjkcwsxopludrj5ttmtm7mzfqsugmxdnqevqso7o",
            "mainnet": "bafk2bzaceaipvjhoxmtofsnv3aj6gj5ida4afdrxa4ewku2hfipdlxpaektlw",
            "testing": "bafk2bzacecqk6zlwein7tzy7yrrhtj4pzavrkofgpyxvvw5ktr3w4x4ml4lis",
            "testing-fake-proofs": "bafk2bzacebwkqd6e7gdphfzw2kdmbokdh2bly6fvzgfopxzy7quq4l67gmkks"
        },
        "multisig": {
            "butterflynet": "bafk2bzacectfmzjtniypgl4whm42sws5aupihqgfikwsr7p5yoq3bmqaogldi",
            "calibrationnet": "bafk2bzacec66wmb4kohuzvuxsulhcgiwju7sqkldwfpmmgw7dbbwgm5l2574q",
            "caterpillarnet": "bafk2bzaceb3kh5hjh6eebb5236xp7crn2owyyo7irap6sy4ns76uc7om6pxuy",
            "devnet": "bafk2bzaced4gcxjwy6garxwfw6y5a2k4jewj4t5nzopjy4qwnimhjtnsgo3ss",
            "mainnet": "bafk2bzacebhldfjuy4o5v7amrhp5p2gzv2qo5275jut4adnbyp56fxkwy5fag",
            "testing": "bafk2bzacea5zp2g6ag5qfuro7zw6kyku2swxs57wjxncaaxbih5iqflqy4ghm",
            "testing-fake-proofs": "bafk2bzacea5zp2g6ag5qfuro7zw6kyku2swxs57wjxncaaxbih5iqflqy4ghm"
        },
        "paymentchannel": {
            "butterflynet": "bafk2bzacecbwu54ce5mjgp2pqxyj6kpn2vlgiu5wv2lj2byjiegxnn3infd5i",
            "calibrationnet": "bafk2bzaceblot4pemhfgwb3lceellwrpgxaqkpselzbpqu32maffpopdunlha",
            "caterpillarnet": "bafk2bzacedl5am53e4mtxpzligcycxvmkolfkhfiuavww2dq3ukgaqwowj7vw",
            "devnet": "bafk2bzaceb3isfguytt6cs4xecyoonbhhekmngfbap2msggbwyde7zch3a6w4",
            "mainnet": "bafk2bzacebalad3f72wyk7qyilvfjijcwubdspytnyzlrhvn73254gqis44rq",
            "testing": "bafk2bzaced47dbtbygmfwnyfsp5iihzhhdmnkpuyc5nlnfgc4mkkvlsgvj2do",
            "testing-fake-proofs": "bafk2bzaced47dbtbygmfwnyfsp5iihzhhdmnkpuyc5nlnfgc4mkkvlsgvj2do"
        }
    });
}

pub fn actor_code_included(actor_code: &str, actor_type: String) -> bool {
    match ACTOR_CODE_CIDS[actor_type]
        .as_object()
        .unwrap()
        .values()
        .rfind(|x| x.as_str().unwrap() == actor_code)
    {
        Some(_) => true,
        None => false,
    }
}

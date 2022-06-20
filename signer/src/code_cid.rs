use serde_json::{json, Value};
use lazy_static::lazy_static;

lazy_static! {
    pub static ref ACTOR_CODE_CIDS: Value = json!(
    {
        "init": {
            "butterflynet": "bafk2bzacebjzrzjtrq7fops45chsb5xwr2ljmsbpn6rdhaeofhgazqfnnnvia",
            "calibrationnet": "bafk2bzaceadyfilb22bcvzvnpzbg2lyg6npmperyq6es2brvzjdh5rmywc4ry",
            "caterpillarnet": "bafk2bzacedrygc7pawj6rgfy5uawgfkykias2phw7lgjfj7yyxtfpk3wsyj7c",
            "devnet": "bafk2bzacedetk52vj6vfpqw3wfd5shnkfigokmyhrfojhtvz43336m43thham",
            "mainnet": "bafk2bzacecxkeddlvo5azclqbasrlymu3a2k3y6jsbaeov4lix5pwzdra5bek",
            "testing": "bafk2bzacecioxkb2gqaze7lnaq7xj2aibiqgapl4jq2qyccjbvuzanzzkwqnc",
            "testing-fake-proofs": "bafk2bzacebwfsgvfuuogwodiq53m23ggae5saavabeqouttmo6s52pdmzmg36"
        },
        "multisig": {
            "butterflynet": "bafk2bzacecumdo2d2vpmkd66vqdkj32zu6m54ddpaqiqcchybq7fljygips6e",
            "calibrationnet": "bafk2bzacec66wmb4kohuzvuxsulhcgiwju7sqkldwfpmmgw7dbbwgm5l2574q",
            "caterpillarnet": "bafk2bzacececbmijm2t4uemwgrspnnslpgnksozvshrwgf3ozh6zncz7aqr4c",
            "devnet": "bafk2bzacebtypmb6dqnhowzttf643kbgtdhf6iclasc4ffxkkq5atriqc42g6",
            "mainnet": "bafk2bzacebqhfu4doyffwknjsw7vjldpkccf253i6sncx6ty7ofm2q3d2ttys",
            "testing": "bafk2bzacecyeqb2ilsuoxfphqpfxrtwaz7vfbrq3kq67j5uof6sbrw675zbry",
            "testing-fake-proofs": "bafk2bzacecyeqb2ilsuoxfphqpfxrtwaz7vfbrq3kq67j5uof6sbrw675zbry"
        },
        "paymentchannel": {
            "butterflynet": "bafk2bzacecmsfeq364zbysebk4xkpmtcxe4bv4lrlfdzidqoudnsdihph4d6u",
            "calibrationnet": "bafk2bzaceblot4pemhfgwb3lceellwrpgxaqkpselzbpqu32maffpopdunlha",
            "caterpillarnet": "bafk2bzacedv3lmu3ut7nrl5zpxl22je2qiognakt3m4eibux4x74nwibdegeu",
            "devnet": "bafk2bzacedvd4cfhfz7duxkudnu2cxbqkmanodgvpf623jmtz75njif5d5d3a",
            "mainnet": "bafk2bzacebk5kb6ofhksspgv3wp6uwbcrn7x37ego54bgakywseg7bgw4ffdq",
            "testing": "bafk2bzacedsi4nwln57uqf2vhjma3qfsmavjhyjwk6bch2nl3zbwmwln3cgk6",
            "testing-fake-proofs": "bafk2bzacedsi4nwln57uqf2vhjma3qfsmavjhyjwk6bch2nl3zbwmwln3cgk6"
        }
    });
}

pub fn actor_code_included(actor_code: &str, actor_type: String) -> bool {
    match ACTOR_CODE_CIDS[actor_type].as_object().unwrap().values().rfind(|x| x.as_str().unwrap() == actor_code) {
        Some(_) => true,
        None => false,
    }

} 
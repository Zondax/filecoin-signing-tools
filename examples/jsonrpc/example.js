const axios = require('axios');

const URL = "http://127.0.0.1:3030/v0";
const JWT = "";

async function main() {
    try {
        const answer = await axios.post(
            URL,
            {
                jsonrpc: '2.0',
                method: `key_generate`,
                params: [],
                id: 1,
            },
            {
                headers: {
                    'Content-Type': 'application/json',
                    Accept: '*/*',
                    Authorization: `Bearer ${JWT}`,
                },
            },
        );
        return answer.data;
    }
    catch(e) {
        return e.message;
    }
}

main()
    .then(out => console.log(out))
    .catch(err => console.error(err));

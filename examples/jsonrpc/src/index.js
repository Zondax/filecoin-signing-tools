const axios = require('axios');

export async function callMethod(url, method, params, id, jwt = "") {
    try {
        const answer = await axios.post(
            url,
            {
                jsonrpc: '2.0',
                method: `${method}`,
                params: [...params],
                id,
            },
            {
                headers: {
                    'Content-Type': 'application/json',
                    Accept: '*/*',
                    Authorization: `Bearer ${jwt}`,
                },
            },
        );
        return answer.data;
    }
    catch(e) {
        return e.message;
    }
}

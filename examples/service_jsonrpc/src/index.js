const axios = require("axios");

export async function callMethod(url, method, params, id, jwt = "") {
    const headers = {
        headers: {
            "Content-Type": "application/json",
            Accept: "*/*",
            Authorization: `Bearer ${jwt}`,
        },
    }

    const answer = await axios.post(
        url,
        {
            jsonrpc: "2.0",
            method: `${method}`,
            params,
            id,
        },
        {
            headers,
        },
    );
    return answer.data;
}

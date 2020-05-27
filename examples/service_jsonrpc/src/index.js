const axios = require("axios");

export async function callMethod(url, method, params, id, jwt = "") {
  const answer = await axios.post(
    url,
    {
      jsonrpc: "2.0",
      method: `${method}`,
      params,
      id,
    },
    {
      headers: {
        "Content-Type": "application/json",
        Accept: "*/*",
        Authorization: `Bearer ${jwt}`,
      },
    },
  );
  return answer.data;
}

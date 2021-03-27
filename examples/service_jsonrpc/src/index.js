const axios = require('axios')

export async function callMethod(url, method, params, id, jwt = '') {
  const config = {
    headers: {
      'Content-Type': 'application/json',
      Accept: '*/*',
    },
  }

  // Include JWT
  if (jwt.length > 0) {
        config.headers['Authorization'] = `Bearer ${jwt}`
  }

  const postData = {
    jsonrpc: '2.0',
    method: `${method}`,
    params,
    id,
  }

  console.log("=================")
  console.log(url, postData, config)

  const answer = await axios.post(url, postData, config)

  console.log(answer.data)

  return answer.data
}

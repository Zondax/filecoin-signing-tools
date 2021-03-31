These testcases expect:

- A running devnet
  
- Funds in address `t137sjdbgunloi7couiy4l5nc7pd6k2jmq32vizpy`

    ```shell
    lotus send t137sjdbgunloi7couiy4l5nc7pd6k2jmq32vizpy 10000
    ```

    Wait a few seconds. You can then check the balance with
 
    ```shell
    lotus wallet balance t137sjdbgunloi7couiy4l5nc7pd6k2jmq32vizpy
    ```

- to update the JWT token you are using in CI

    ```shell
    lotus auth api-info --perm admin
    ```
    
    you will get something like: `FULLNODE_API_INFO=JTWJTWJTWJTWJTJWJTWJWT:/ip4/0.0.0.0/tcp/1234/http`
  Take **only** the JWT token and update `LOTUS_SECRET_TOKEN` in your CI.
  
- if you want to run thinks locally: copy `filecoin-service_template.toml` to `filecoin-service.toml` and adjust URL and TOKEN.


# Crypto Oracle Server

Source code for _crypto oracle_ FastAPI server.

## Running server locally

1. Clone the whole repository:

    ```cmd
    git clone https://github.com/mcagalj/CNS-2023-24.git
    ```

2. Navigate to folder `crypto-oracle`.
3. Open the folder in Visual Studio Code (VSC).
   > VSC should automatically start a developent container. If not, use `Dev Container: Reopen in Container` option; assuming you have installed Dev Container extension in VSC.
4. Once the dev container is up and running, open the command shell in VSC and start _crypto oracle_ server as follows:

   ```bash
   make dev-fastapi
   ```

    or more directly:

    ```bash
    uvicorn app.main:app --reload
    ```

    The server should be accessible on port `8000` on your `localhost` machine; VSC should automatically forward the port `8000`. In case of errors due to missing Python packages, try to install them manually.

> NOTE: All secrets, challenges, cookies and other configuration information used by _crypto oracle_ server can be found in file `settings.yaml`.

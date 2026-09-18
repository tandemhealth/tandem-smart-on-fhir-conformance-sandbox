"""`smart-sandbox` console script: start the sandbox with uvicorn."""

import argparse

import uvicorn


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="smart-sandbox",
        description="Run the SMART on FHIR conformance sandbox.",
    )
    parser.add_argument("--port", type=int, default=8090)
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Interface to listen on. Keep the default while "
        "SANDBOX_ALLOW_PRIVATE_NETWORK is enabled.",
    )
    args = parser.parse_args()
    # uvicorn's access log prints full URLs, which here carry the dashboard
    # bootstrap token and OAuth codes. The app logs method, path and status
    # itself (see api.py) without the query string.
    uvicorn.run(
        "smart_sandbox.api:app", host=args.host, port=args.port, access_log=False
    )


if __name__ == "__main__":
    main()

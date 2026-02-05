import inspect
from cpgqls_client import CPGQLSClient
import asyncio

print(f"Is execute a coroutine? {inspect.iscoroutinefunction(CPGQLSClient.execute)}")

try:
    client = CPGQLSClient("localhost:9001")
    # check internal method _send_query if possible
    if hasattr(client, "_send_query"):
         print(f"Is _send_query a coroutine? {inspect.iscoroutinefunction(client._send_query)}")
except:
    pass

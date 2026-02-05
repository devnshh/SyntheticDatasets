
import asyncio
import websockets
import os
import shutil
import aiofiles

# Config
PORT = 9005
WORKSPACE = "/tmp/joern_debug"

async def test_joern():
    # 1. Setup Workspace
    if os.path.exists(WORKSPACE):
        shutil.rmtree(WORKSPACE)
    os.makedirs(WORKSPACE)
    
    # 2. Create Dummy Code
    code_path = os.path.join(WORKSPACE, "test.java")
    async with aiofiles.open(code_path, "w") as f:
        await f.write("public class Test { public void main(String[] args) { System.out.println(\"Hello\"); } }")
        
    # 3. Start Server
    print("Starting Joern Server...")
    cmd = ["joern", "--server", "--server-port", str(PORT)]
    process = await asyncio.create_subprocess_exec(
        *cmd,
        cwd=WORKSPACE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    
    # 4. Connect
    uri = f"ws://localhost:{PORT}/connect"
    conn = None
    try:
        # Retry connect
        for i in range(10):
            try:
                conn = await websockets.connect(uri)
                print("Connected!")
                break
            except Exception:
                await asyncio.sleep(1)
                
        if not conn:
            print("Failed to connect")
            return

        # 5. Wait for Handshake
        print("Waiting for handshake...")
        while True:
            msg = await conn.recv()
            print(f"Received handshake: {msg}")
            if "connected" in msg:
                break

        # 6. Send Basic Query
        query = '1+1'
        print(f"Sending: {query}")
        await conn.send(query)

        # 7. Wait for Response (with timeout)
        try:
             # Also read stdout/stderr from server
            async def read_stream(stream, name):
                while True:
                    line = await stream.readline()
                    if line:
                        print(f"[{name}] {line.decode().strip()}")
                    else:
                        break
            
            asyncio.create_task(read_stream(process.stdout, "STDOUT"))
            asyncio.create_task(read_stream(process.stderr, "STDERR"))

            while True:
                resp = await asyncio.wait_for(conn.recv(), timeout=30)
                print(f"Received: {resp}")
                if "connected" not in resp:
                    break
        except asyncio.TimeoutError:
            print("❌ TIMEOUT waiting for validation!")
            
    except Exception as e:
        print(f"Error: {e}")
    finally:
        if conn: await conn.close()
        process.terminate()
        await process.wait()

if __name__ == "__main__":
    asyncio.run(test_joern())

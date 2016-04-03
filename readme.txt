1. Debug mode (You need to add --debug on both server and client side)
Server:
./server --port 41492 --debug [--ipv6]
Client:
./client --server localhost --port 41492 --user Ali --pwd 654321 --debug --query Finland

2. Authentication mode (which is normal mode, the normal command line flag is optional, in default it is normal mode)
Server:
./server --port 41492 [--normal]
Client:
./client --server localhost --port 41492 --user Ali --pwd 654321 [--normal] --query Sweden

3. Concurrency (In this mode, the server will not close after one client finish the query, so more clients can
query to the server)
Server:
./server --port 41492 --concurrency
Client Now support more than one client to query:
./client --server localhost --port 41492 --user Mengyang --pwd 123456 --normal --query Norway
./client --server localhost --port 41492 --user Ali --pwd 654321 --normal --query Norway

4. IPV6 (You should add ipv6 flag on both side)
Server:
./server --port 41492 --ipv6
./client --server localhost --port 41492 --user Ali --pwd 654321 --ipv6 --query Denmark
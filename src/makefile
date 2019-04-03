All: Keytool FileServer FileClient

Keytool:
	gcc Keytool.c -lssl -o Keytool

FileServer:
	gcc FileServer.c common.c -lpthread -lssl -o FileServer
	mv FileServer ../server

FileClient:
	gcc FileClient.c common.c -lssl -o FileClient
	mv FileClient ../client
clean:
	rm -f Keytool ../FileServer ../FileClient

CSCE 3550 Project 3: Bulking up our JWKS Server

This is a JWKS server that has been implented using a RESTful HTTP API that was created using Python 3.11. The server runs on a local port and generates an RSA key pair, JWT with a key ID, and stores them in a JWKS list. These keys are then stored in a database using SQLite3 and can be retrieved from the database as well.In this last version we've bulked up the server by adding multiple databases that the code can access as well as stronger encryption methods to keep our information safe from attackers. I've also implemented a rate limiter that serves to protect the server from becoming overwhelemed. 

The code was provided by the staff and my code is built off of it.

First verify the gradebot.exe executable is located in the same file as the main.py. To run the server type py main.py and it will begin. Once the server is being ran on another terminal located in the same folder you can run ./gradebot project2 and it will automatically grade and show results of the server.

To run the test suite simply time

py -m unittest main.py then coverage report -m
and youll see the ouput

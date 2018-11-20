# README

## Overview

This repository contains code which demonstrates the use of the OpenSSL library for secure network communication between the client and server. This code also makes use of the common `libxml2` library to handle XML parsing.

## demo1

This is a simple example of an SSL application. The server starts listening on the port passed on the commandline. When a connection is made and a short XML snippet containing the *username* and *password* the server looks up these values in the `db.xml` XML file and if the user and password are valid, the contents of the `<response>` tag are returned to the client.

### Build it

For Debug: 

    mkdir cmake-build-debug
    cmake -DCMAKE_BUILD_TYPE=Debug ..
    make
    
For Release:

    mkdir cmake-build-release
    cmake ..
    make
    
### Server

Start the server as follows:
    
    cd cmake-build-debug/demo1/server/
    ./demo1_server 5000 # Run the server listening on port 5000

When a connection is made the server will dump some information about the connection including the XML snippet containing the user credentials.

### Client

Start the client as follows:

    cd cmake-build-debug/demo1/client
    ./demo1_client localhost 5000

### Unit test

A Python unit test is provided which launches the SSL server in the Test Cases `setUp` function and kills it when the `tearDown` of the test case happens. The single test runs the SSL client and sends a user/password pair and the returned result is evaluated for success or failure.

To run the test

    cd test
    ./run_unit_test.sh

## Monitor Packet Traffic w/tcpdump

To make sure that the network traffic is really encrypted by the SSL library you can run the `tcpdump` command to monitor all traffic on port `5000` of the `lo` interface by issuing the following command: 

    sudo tcpdump -i lo -nnXSs 0 port 5000
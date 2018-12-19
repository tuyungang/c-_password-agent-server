#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <cassert>
#include <signal.h>
#include <sys/time.h>
#include "agent_main.h"

void StartAgentServer()
{
    AgentMain *agent = AgentMain::GetInstance();
    //agent->Startup();
    agent->run();
}

void QuitAgentServer()
{

}

int main( int argc, char* argv[] )
{
    StartAgentServer();
    QuitAgentServer();
    return 0;
}

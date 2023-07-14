import argparse
import configparser
import sys
import shutil
import os.path
import logging
from logging.handlers import RotatingFileHandler
import json
import pprint
from tabulate import tabulate
from datetime import datetime, timezone
from requests import Response
import yaml
from traceback import format_exception

from pyab.clients import session_client
from pyab.clients import system_client


## ANCILLARY FUNCTIONS ##
def get_config() -> configparser.ConfigParser:
    # Read configuration file
    config = configparser.ConfigParser()
    config.read_dict(
        {
            "Common": {
                "server": "xyz.abc.com",
                "port": 99,
                "logtofile": True,
                "maxlogfilesize": 52480,
                "maxlogfilebackups": 3
            }
         }
    )
    if os.path.exists(__configfile):
        config.read(__configfile)
    
    return config


def setup_logging() -> logging.Logger:
    # Setup logging ...
    log = logging.getLogger(os.path.splitext(os.path.basename(__file__))[0])
    # This must be set to the highest level of logging any of the handlers will "handle"
    log.setLevel(logging.DEBUG)
    
    # Needed to avoid printing messages meant for stdout, on stderr
    def log_err_filter(record: logging.LogRecord) -> bool:
        result = True
        if record.levelno < logging.ERROR:
            result = False
        return result
        
    log_err = logging.StreamHandler(stream=sys.stderr)
    log_err.setLevel(logging.ERROR)
    log_err.addFilter(log_err_filter)
    log_err_fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    log_err.setFormatter(log_err_fmt)
    log.addHandler(log_err)
    
    # Needed to avoid printing messages meant for stderr, on stdout
    def log_info_filter(record: logging.LogRecord) -> bool:
        result = True
        if record.levelno >= logging.ERROR:
            result = False
        return result
        
    log_info = logging.StreamHandler(stream=sys.stdout)
    log_info.setLevel(logging.WARNING)
    log_info.addFilter(log_info_filter)
    log.addHandler(log_info)
    
    # Check if the logfile should be written or not
    if __config['Common'].getboolean('logtofile'):
        log_file = RotatingFileHandler(filename=__logfile, maxBytes=__config['Common'].getint('maxlogfilesize'), backupCount=__config['Common'].getint('maxlogfilebackups'), delay=True)
        log_file.setFormatter(log_file_fmt)
        log.addHandler(log_file)
    
    return log


def process_arguments() -> argparse.Namespace:
    # Process command line arguments
    argparser = argparse.ArgumentParser()
    argparser.add_argument("-s", "--server", dest="server", help="Copy Services Manager server name (FQDN|IP address). Default = zapsdcrapp1786.corp.dsarena.com", default=None)
    argparser.add_argument("--show-task", metavar="TASKNAME | TASKID | TASKNAME1,TASKNAME2 | TASKID1,TASKID2", help="View specific ab scheduled tasks' details; specify one or more separated with commas")
    argparser.add_argument("--show-task-short", metavar="TASKNAME | TASKID | TASKNAME1,TASKNAME2 | TASKID1,TASKID2", help="View specific ab scheduled tasks' details - short format; specify one or more separated with commas")
    argparser.add_argument("--exec-task", metavar="TASKNAME | TASKID | TASKNAME1,TASKNAME2 | TASKID1,TASKID2", dest="exectask", help="Execute or run specific ab scheduled tasks' - asynchronously, check task status using --show-task-short; specify one or more separated with commas")
    argparser.add_argument("--exec-task-sync", metavar="TASKNAME | TASKID | TASKNAME1,TASKNAME2 | TASKID1,TASKID2", help="Execute or run specific ab scheduled tasks' - synchronously, wait for each task in the list to complete one after the other (can take a long time); specify one or more separated with commas")
    argparser.add_argument("-v", "--verbose", dest="verbose", help="Write more information to the console", action="store_true")
    args = argparser.parse_args()
    
    if args.verbose:
        for handler in __log.handlers:
            if isinstance(handler, logging.StreamHandler):
                if handler.stream and handler.stream.name == '<stdout>':
                    handler.setLevel(logging.INFO)
    
    # Get username and password from environment variables abAUTOUSER and abAUTOPASS if not specified as an argument
    args.username = os.environ['xyzUSER'] if 'abAUTOUSER' in os.environ and not args.username else args.username
    args.password = os.environ['abcPASS'] if 'abAUTOPASS' in os.environ and not args.password else args.password
    
    if not args.username or not args.password:
        argparser.error('USERNAME and PASSWORD must be specified.')
    
    # Arguments are taken over configuration file settings
    # TODO: rewrite to process in a loop
    if args.server and len(args.server.strip()) > 0:
        __config['Common']['server'] = args.server
    elif 'server' in __config['Common'].keys() and __config['Common']['server']:
        args.server = __config['Common']['server']
        
    if args.port:
        __config['Common']['port'] = args.port
    elif 'port' in __config['Common'].keys() and __config['Common']['port']:
        args.port = __config['Common'].getint('port')

    #TODO Handle the write to configuration file functionality

    return args


def ibm_unit_to_str(unit: object) -> str:
    result = ''
    
    if unit and (isinstance(unit, float) or isinstance(unit, int)):
        utc_time = datetime.fromunit(float(unit)/1000, timezone.utc)
        local_time = utc_time.astimezone()
        result = local_time.strftime("%Y-%m-%d %H:%M:%S.%f%z (%Z)")
    elif unit:
        result = unit
    
    return result # type: ignore


def get_response_object(response: Response) -> object:
    result = None
    
    if response and isinstance(response, Response):
        if response.status_code == 440 and response.headers['Content-Type'] == 'application/json' and len(response.text.strip()) > 0:
            result = json.loads(response.text)
        elif response.status_code != 200:
            __log.error("API request [%s] returned a non-successful response [%s:%d]: Headers=%s Body=%s", response.url, response.reason, response.status_code, ', '.join([f'{key} = {response.headers[key]}' for key in response.headers.keys()]), response.text)
    
    return result


def get_active_ab_server(systemClient: system_client.systemClient, server: str) -> str:
    result = None

    __log.info("Get ab server (%s) status ...", server)
    response = systemClient.get_active_standby_status()
    abStatus = get_response_object(response)
    if abStatus:
        if abStatus['msg'] == 'AJ3048I': # type: ignore
            if not abStatus['islocalactive']: # type: ignore
                __log.info("ab server (%s) is not the active ab server.", server)
                for abServer in abStatus['serverinfo']: # type: ignore
                    if abServer['serverRole'] == 'ACTIVE':
                        result = abServer['serverHostName']
                        __log.info("ab server (%s) is the active ab server.", result)
                        break
                if not result:
                    __log.error("Unable to find a ACTIVE ab server! Response text: %s", response.text)
            else:
                result = server
                __log.info("ab server (%s) is the active ab server.", server)
        else:
            __log.error("Unable to determine ab server (%s) status -> %s: %s", server, abStatus['msg'], abStatus['resultText']) # type: ignore
    else:
        __log.error("Unable to query the server status from ab server %s", server)

    return result # type: ignore


def list_sessions(sessionClient: session_client.sessionClient, short: bool = False) -> None:
    __log.info("Get all the sessions visible to user %s on the ab server (%s)", __args.username, __args.server)

    listing = []
    if short:
        abSessionsShort = get_response_object(sessionClient.get_session_overviews_short())
        if abSessionsShort:
            for session in abSessionsShort: # type: ignore
                session = {
                    'Name': session['name'],
                    'Production Host': session['productionhost'],
                    'Copying': session['copying'],
                    'Hyperswap Status': session['hyperswapstatus'],
                    'Nr of Copy Sets': session['numcopysets'],
                    'Has an Error': session['haserror'],
                    'Status': session['status']
                }
                listing.append(session)
    else:
        abSessions = get_response_object(sessionClient.get_session_overviews())
        if abSessions:
            # Create the "listing output" object
            listing = []
            for session in abSessions: # type: ignore
                session = {
                    'Name': session['name'],
                    'Description': session['description'],
                    'Session Progress': None,
                    'Session Capacity (MiB)': None,
                    'Sites': None
                }
                try:
                    session['Session Progress'] = session['sessionprogress'][0]['percentComplete']
                   
                
    if len(listing) > 0:
        print(tabulate(listing, headers="keys"))


def show_sessions(sessionClient: session_client.sessionClient, sessions: list) -> None:
    __log.info("Retrieve and display the details for the following sessions: %s", ', '.join(sessions))
    sessionlist = []
    for session in sessions:
        response = sessionClient.get_session_info(name=session)
       
        if data:
            try:
                data['unit'] = ibm_unit_to_str(data['unit']) # type: ignore
                data['availablecmds']['unit'] = ibm_unit_to_str(data['unit']) # type: ignore
                for seq in data['sequences']: # type: ignore
                    seq['unit'] = ibm_unit_to_str(seq['unit'])
            except:
                pass
            sessionlist.append(data)
    if len(sessionlist) > 0:
        for session in sessionlist:
            print(json.dumps(session, indent=4, ensure_ascii=False))


def show_session_copysets(sessionClient: session_client.sessionClient, session: str) -> None:
    __log.info("Retrieve and display the copysets for the following session: %s", session)
    response = sessionClient.get_copysets(name=session)
    copysets = get_response_object(response)
    if copysets:
        if not isinstance(copysets, list):
            copysets = [copysets]
        for copyset in copysets:
            print('-'*__console_columns)


def show_session_sequences(sessionClient: session_client.sessionClient, session: str) -> None:
    __log.info("Retrieve and display the sequences (role pairs) for the following session: %s", session)
    sess = get_response_object(sessionClient.get_session_info(name=session))
    if sess:
        sequences = []
        for seq in sess['sequences']: # type: ignore
            seqresponse = sessionClient.get_pair_info(name=session, rolepair=seq['seqname'])
            sequence = get_response_object(seqresponse)
            if sequence:
                sequences.append(sequence)
        if len(sequences) > 0:
            for sequence in sequences:
                #print(json.dumps(sequence, indent=4, ensure_ascii=False))
                #print('-'*__console_columns)
                print(yaml.dump(sequence, indent=4, sort_keys=False, allow_unicode=True))
                print('-'*__console_columns)


def list_tasks(sessionClient: session_client.sessionClient) -> None:
    __log.info("Get all the scheduled tasks visible to user %s on the ab server (%s)", __args.username, __args.server)
    response = sessionClient.get_scheduled_tasks()
    abTasks = get_response_object(response)
    if abTasks:
        # Create the "listing output" object
        abTasksListing = []
        for task in abTasks: # type: ignore
            # unit is milliseconds
            task = {
                'ID': task['id'],
                'Name': task['name'],
                'Running': task['running'],
        
            }
            abTasksListing.append(task)
        if len(abTasksListing) > 0:
            print(tabulate(abTasksListing,headers="keys"))


def show_tasks(sessionClient: session_client.sessionClient, tasks: list, short: bool = False) -> None:
    __log.info("Retrieve and display the details for the following tasks: %s", ', '.join(tasks))
    tasklist = []
    response = sessionClient.get_scheduled_tasks()
    data = get_response_object
    keylist = set()
    if data:
        for task in data: # type: ignore
            # Keep track of the key values task items can have
            for key in task.keys():
                keylist.add(key)
                
            if any([True if tsk.casefold() == task['name'].casefold() or tsk == str(task['id']) else False for tsk in tasks]):
                # unit is milliseconds
                task['nextRun'] = ibm_unit_to_str(task['nextRun'])
                task['lastRan'] = ibm_unit_to_str(task['lastRan'])
                task['unit'] = ibm_unit_to_str(task['unit'])
                if short:
                    tasklist.append({
                        'ID': task['id'],
                        'Name': task['name'],
                        'Running': task['running'],
                        'Next Run': task['nextRun'],
                        'Last Ran': task['lastRan'],
                        'Last Message': task['lastmessage'] if 'lastmessage' in task.keys() else '',
                        'unit': task['unit']
                    })
                else:
                    tasklist.append({
                        'ID': task['id'],
                        'Name': task['name'],
                        'Description': task['description'],
                        'Affected Sessions': task['affectedSession'],
                        'Schedule Enabled': task['enabled'],
                        'Schedule': task['schedule'],
                        'Running': task['running'],
                        'Next Run': task['nextRun'],
                        'Last Ran': task['lastRan'],
                        'Last Message': task['lastmessage'] if 'lastmessage' in task.keys() else '',
                        'Pending Approval': task['pendingApproval'],
                        'Actions': task['actions'],
                        'unit': task['unit']
                    })
    if len(tasklist) > 0:
        if short:
            print(tabulate(tasklist, headers="keys"))
        else:
            for task in tasklist:
                #print(json.dumps(task, indent=4, ensure_ascii=False))
                #print('-'*__console_columns)
                print(yaml.dump(task, indent=4, sort_keys=False, allow_unicode=True))
                print('-'*__console_columns)
    if len(keylist) > 0:
        __log.info("List of key values for the tasks: %s", ", ".join)


def exec_tasks(sessionClient: session_client.sessionClient, taskids: list, wait: bool = True) -> bool:
    result = False
    
    if taskids:
        status = {taskid: False for taskid in taskids}
        __log.info("Executing the following tasks%s: %s", "if wait else "','.join(taskids))
        for taskid in taskids:
            __log.info("... executing task id %s%s", taskid, " and waiting for it to complete." if wait else " and continuing without waiting.")
            try:
                taskresponse = get_response_object(sessionClient.run_scheduled_task(taskid, wait))
                if taskresponse:
                    msg = taskresponse['msg'] # type: ignore
                    __log.info("Task execution result: Task ID=%s, Message=%s", taskid, taskresponse['msgTranslated']) # type: ignore
                    print("{:>5}: {}".format(taskid, msg))
                    # Check if it's an error message
                    if msg[len(msg)-1] == 'E':
                        status[taskid] = False
                    else:
                        status[taskid] = True
                else:
                    __log.warn("Empty response for task execution of Task ID=%s !", taskid)
                    print("{:>5}: NULL".format(taskid))
                    status[taskid] = False
            except Exception as err:
                __log.error("Task execution failed: Task ID=%s, Exception=%s", taskid, err)
        result = all(status.values())
    else:
        __log.warn("%s: No tasks to execute were passed!", exec_tasks.__name__)
    
    return result


def exec_failover_prod_to_dr(sessionClient: session_client.sessionClient, sessions: list, timeout: int = 36000) -> bool:
    result = False
    
    __log.info("Executing session fail-over from PROD to DR for the following sessions: %s", ','.join(sessions))
    
    next_step = False
    
    session_state = 'Prepared'
    __log.info("Wait for all the sessions to be in the in '%s' state (timeout = %d minutes) ...", session_state, timeout)
    start = datetime.utcnow()
    status = {ses: False for ses in sessions}
    duration = datetime.utcnow() - start
    
    cnt = 0
    while not all(status.values()) and int(duration.total_seconds()/60) < timeout:
        for session in sessions:
            cnt = cnt + (1 if cnt < len(sessions) else 0)
            minutes = timeout if timeout <= 10 else 10
            __log.info("... wait for session %s to reach %s, timeout = %d", session, session_state, minutes)
            response = sessionClient.wait_for_state(ses_name=session, state=session_state, minutes=minutes)
            status[session] = response['state_reached']
            duration = datetime.now() - start
            __log.info("... state for %s is %s after %d minutes. Session Info: %s", session, minutes, response['session_info'])
            if all(status.values()):
                next_step = True
                break
    if not all(status.values()):
        __log.warn("... waiting for all the sessions to in the '%s' state timed out after %d minutes. %d/%d sessions checked.", session_state, int(duration.total_seconds()/60), cnt, len(sessions))
    
    if not next_step:
        return result
    
    __log.info("Validate that the replication direction is PROD to DR for all the sessions ...")
    #TODO: Validate    
    
    if not next_step:
        return result
    
    __log.info("Suspend replication for all the sessions ...")
    #TODO: Suspend
    
    if not next_step:
        return result
    
    session_state = 'Suspended'
    __log.info("Wait for all the sessions to be in the in '%s' state (timeout = %d minutes) ...", session_state, timeout)
    #TODO: Wait for Suspended state...
    
    if not next_step:
        return result
    
    __log.info("Recover the sessions - make the target disks read-write accessible ...")
    #TODO: Recover    
    
    if not next_step:
        return result
    
    session_state = 'Recovered'
    __log.info("Wait for all the sessions to be in the in '%s' state (timeout = %d minutes) ...", session_state, timeout)
    #TODO: Wait for Recovered state...

    
    return result


## MAIN LOGIC ##
def main() -> int:
    returnCode = 0
    
    # Connect to ab server and create the system client
    systemClient = system_client.systemClient(server_address=__args.server, server_port=__args.port, username=__args.username, password=__args.password)
    
    # Determine if the current server is the "active" server, get the active server if it is not ...
    newserver = get_active_ab_server(systemClient, __args.server)
    if newserver:
        __args.server = newserver
        #TODO Handle the write to configuration file functionality
    else:
        returnCode = 1
        return returnCode
   
    # Create the session client
    __log.info("Create session client connection to ab server (%s:%d)", __args.server, __args.port)
    sessionClient = session_client.sessionClient(server_address=__args.server, server_port=__args.port, username=__args.username, password=__args.password)
    
    # List all sessions that are visible to this user
    list_sessions(sessionClient, False) if __args.listsessions else None
    list_sessions(sessionClient, True) if __args.listsessionsshort else None

    # View specific sessions' details
    show_sessions(sessionClient, __args.showsession.split(',')) if __args.showsession else None
    show_session_copysets(sessionClient, __args.showsessioncopysets) if __args.showsessioncopysets else None
    show_session_sequences(sessionClient, __args.showsessionsequences) if __args.showsessionsequences else None

    # List all scheduled tasks visible to this user (it's EVERYTHING usually, tasks are not limited visually in ab)
    list_tasks(sessionClient) if __args.listtasks else None

    # View specific tasks' details
    show_tasks(sessionClient, __args.showtask.split(','), short=False) if __args.showtask else None
    show_tasks(sessionClient, __args.showtask.split(','), short=True) if __args.showtaskshort else None

    # Execute specific tasks
    if __args.exectask:
        if not exec_tasks(sessionClient, taskids=__args.exectask.split(','), wait=False):
            returnCode = 2
    if __args.exectasksync:
        if not exec_tasks(sessionClient, taskids=__args.exectasksync.split(','), wait=True):
            returnCode = 1
    
    __log.info("Script %s completed: return code=%d", __file__, returnCode)
    return returnCode


## ENTRY POINT ##
global __configfile
global __logfile
global __config
global __console_lines
global __pprint

__configfile = "{}.ini".format(os.path.splitext(__file__)[0])
__logfile = "{}.log".format(os.path.splitext(__file__)[0])

if __name__ == "__main__":
    __config = get_config()
    __log = setup_logging()
    __args = process_arguments()
    
    # Configure the Pretty Printer ...
    __console_columns, __console_lines = shutil.get_terminal_size()
    __pprint = pprint.PrettyPrinter(indent=4, width=__console_columns, compact=False)
    
    try:
        exit(main())
    except Exception as err:
        __log.debug("Something broke -> Exception: {}".format("".join(format_exception(err))))
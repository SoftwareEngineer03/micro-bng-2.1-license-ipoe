from subprocess import Popen, PIPE
from common import process
from threading import Thread
import time


def micro_bngd_thread_func(micro_bngd_control):
    process = micro_bngd_control["process"]
    print("micro_bngd_thread_func: before communicate")
    (out, err) = process.communicate()
    print(
        "micro_bngd_thread_func: after communicate out=" + str(out) + " err=" + str(err)
    )
    process.wait()
    print("micro_bngd_thread_func: after wait")


def start(micro_bngd, args, bng_cmd, max_wait_time):
    print("micro_bngd_start: begin")
    micro_bngd_process = Popen([micro_bngd] + args, stdout=PIPE, stderr=PIPE)
    micro_bngd_control = {"process": micro_bngd_process}
    micro_bngd_thread = Thread(
        target=micro_bngd_thread_func,
        args=[micro_bngd_control],
    )
    micro_bngd_thread.start()

    # wait until micro-bngd replies to 'show version'
    # micro-bngd needs some time to be accessible
    sleep_time = 0.0
    is_started = False
    while sleep_time < max_wait_time:
        if micro_bngd_process.poll() is not None:  # process is terminated
            print(
                "micro_bngd_start: terminated during 'show version' polling in (sec): "
                + str(sleep_time)
            )
            is_started = False
            break
        (exit, out, err) = process.run([bng_cmd, "show version"])
        if exit != 0:  # does not reply
            time.sleep(0.1)
            sleep_time += 0.1
        else:  # replied
            print("micro_bngd_start: 'show version' replied")
            is_started = True
            break

    return (is_started, micro_bngd_thread, micro_bngd_control)


def end(micro_bngd_thread, micro_bngd_control, bng_cmd, max_wait_time):
    print("micro_bngd_end: begin")
    if micro_bngd_control["process"].poll() is not None: # terminated
        print("micro_bngd_end: already terminated. nothing to do")
        micro_bngd_thread.join() 
        return

    process.run(
        [bng_cmd, "shutdown hard"]
    )  # send shutdown hard command (in coverage mode it helps saving coverage data)
    print("micro_bngd_end: after shutdown hard")

    # wait until micro-bngd is finished
    sleep_time = 0.0
    is_finished = False
    while sleep_time < max_wait_time:
        if micro_bngd_control["process"].poll() is None:  # not terminated yet
            time.sleep(0.01)
            sleep_time += 0.01
            # print("micro_bngd_end: sleep 0.01")
        else:
            is_finished = True
            print(
                "micro_bngd_end: finished via shutdown hard in (sec): "
                + str(sleep_time)
            )
            break

    # micro-bngd is still alive. kill it
    if not is_finished:
        print("micro_bngd_end: kill process: " + str(micro_bngd_control["process"]))
        micro_bngd_control["process"].kill()  # kill -9 if 'shutdown hard' didn't help

    micro_bngd_thread.join()  # wait until thread is finished
    print("micro_bngd_end: end")

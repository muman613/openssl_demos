import unittest
import subprocess
import shlex
import select
#import time
#import os
#import signal
import threading

class SslDemo1Case(unittest.TestCase):
    DEMO1_PATH = "../cmake-build-debug/demo1/"

    @staticmethod
    def wait_for_output(proc: subprocess.Popen, timeout: int):
        """

        :param proc:
        :param timeout:
        :return:
        """
        lines = []
        wait = True

        # Callback for timeout timer
        def timed_out():
            nonlocal wait
            wait = False

        t = threading.Timer(timeout, timed_out)
        t.start()

        y = select.poll()
        y.register(proc.stdout, select.POLLIN)
        while wait is True:
            if y.poll(1):
                line = proc.stdout.readline().decode("UTF-8").strip()
                # print(line)
                lines.append(line)

        return lines

    def setUp(self):
        """
        Setup the test by launching the server.
        :return:
        """
        # print("setup")
        # start the demo1 server
        cmd = self.DEMO1_PATH + "server/demo1_server 5000"
        args = shlex.split(cmd)
        try:
            self.serverProcess = subprocess.Popen(args, stdout=subprocess.PIPE, bufsize=1)
        except ProcessLookupError as err:
            print(err)
        pass

    def tearDown(self):
        """
        Tear down the test case by killing the server.
        :return:
        """
        # print("tearDown")
        if self.serverProcess.poll() is None:
            self.serverProcess.kill()

            out, err = self.serverProcess.communicate()
            # print(out)
            # print(err)

    def test_demo1(self):
        # print("sslDemo1Case::test_demo")
        lines = SslDemo1Case.wait_for_output(self.serverProcess, 2.0)
        # print(lines)
        self.assertTrue("demo1_server is running..." in lines, msg="Server banner not found")

        cmd = self.DEMO1_PATH + "client/demo1_client localhost 5000"
        args = shlex.split(cmd)

        run_result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="UTF-8", input="Michael\nsecret1234\n")
        self.assertEqual(run_result.returncode, 0, msg="client failed")
        if run_result.returncode == 0:
            out = run_result.stdout
            #lines = str(run_result.stdout).split('\n')
            self.assertTrue("Connected with ECDHE-RSA-AES256-GCM-SHA384 encryption" in out, msg="Wrong encryption type")
            self.assertTrue('Issuer: /C=US/ST=California/L=Vallejo/O=SoftwareMagic/CN=Michael/emailAddress=muman613@gmail.com' in out)

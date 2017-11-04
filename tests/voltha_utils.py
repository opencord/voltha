import json
from tests.itests.docutests.test_utils import \
    run_command_to_completion_with_raw_stdout, \
    run_command_to_completion_with_stdout_in_list

class VolthaUtils():
    @staticmethod
    def start_all_containers(name, test=None):
        print "start_all_containers_Start:-----------------------"
        cmd = "./integrations/swarm/test/helpers/start_voltha.sh {}".format(name)
        out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
        if test:
            if rc != 0:
                print err
            test.assertEqual(rc, 0)
            print out
        print "start_all_containers_End:-------------------------"
        return out, err, rc

    @staticmethod
    def stop_all_containers(test=None):
        print "stop_all_containers_Start:------------------------"
        cmd = "./integrations/swarm/test/helpers/stop_and_remove_all_containers.sh"
        out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
        if test:
            if rc != 0:
                print err
            test.assertEqual(rc, 0)
            print out
        print "stop_all_containers_End:--------------------------"
        return out, err, rc

    @staticmethod
    def wait_for_containers_stop(test=None):
        print "wait_for_containers_stop_Start:-------------------"
        cmd = "./integrations/helpers/wait_for.sh 'Waiting for containers to stop' 'test $(docker ps -q | wc -l) -eq 1' 'Unable to stop all containers' 3 20"
        out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
        if test:
            if rc != 0:
                print err
            test.assertEqual(rc, 0)
            print out
        print "wait_for_containers_stop_End:----------------------"
        return out, err, rc
    
    @staticmethod
    def wait_for_voltha_start(name, test=None):
        print "wait_for_voltha_start_Start:-----------------------"
        cmd = "./integrations/swarm/test/helpers/wait_for_voltha.sh {}".format(name)
        out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
        if test:
            if rc != 0:
                print err
            test.assertEqual(rc, 0)
            print out
        print "wait_for_voltha_start_End:------------------------"
        return out, err, rc

    @staticmethod
    def scale_service(prefix, service, count, test=None):
        print "scale_service_Start:-----------------------------"
        cmd = "./integrations/swarm/test/helpers/scale_service.sh {} {} {}".format(prefix, service, count)
        out, err, rc = run_command_to_completion_with_stdout_in_list(cmd)
        if test:
            if rc != 0:
                print err
            test.assertEqual(rc, 0)
            print out
        print "scale_service_End:------------------------------"
        return out, err, rc

    @staticmethod
    def wait_for_instances(prefix, service, count, interval=3, sleep_time=60, test=None):
        print "wait_for_instances_Start:-----------------------"
        cmd = "./integrations/swarm/test/helpers/wait_for_instances.sh {} {} {} {} {}".format(prefix, service, count, interval, sleep_time)
        out, err, rc = run_command_to_completion_with_stdout_in_list(cmd)
        if test:
            if rc != 0:
                print err
            test.assertEqual(rc, 0)
            print out
        print "wait_for_instances_End:-------------------------"
        return out, err, rc

    @staticmethod
    def get_all_instances_of_service(prefix, service, test=None): 
        print "get_all_instances_of_service_Start:-------------"
        cmd = "./integrations/swarm/test/helpers/get_instances.sh {} {}".format(prefix, service)
        out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
        if test:
            if rc != 0:
                print err
            test.assertEqual(rc, 0)
            print out
        print "get_all_instances_of_Service_End:---------------"
        return json.loads(out), err, rc

package org.onosproject.fmt;

import org.apache.karaf.shell.commands.Argument;
import org.apache.karaf.shell.commands.Command;
import org.onosproject.cli.AbstractShellCommand;

import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/**
 * Created by root on 16. 11. 7.
 */
@Command(scope = "onos", name = "flow-fmt",
        description = "Monitoring flows and install firewall rules")
public class FlowMonitoringToolCommand extends AbstractShellCommand {

    private static final int DEFAULT_LASTTIME = 60 * 1000;

    private static final int DEFAULT_MONITORTIME = 2;

    private static final int DEFAULT_FIWARETIME = 10;

    static ScheduledExecutorService schedule = new ScheduledThreadPoolExecutor(1);

    @Argument(index = 0, name = "option", description = "option for choice", required = false, multiValued = false)
    private int option = 0;

    @Argument(index = 1, name = "name", description = "name for out put arff file", required = false, multiValued = false)
    private String name = "test.arff";

    FlowMonitoringTool service = get(FlowMonitoringTool.class);

    @Override
    protected void execute() {

        switch (option) {
            case 0:
                print("welcome to samrt firewall menu please enter 1 to 5");
                print("1 get traffic features each 2 seconds from a switch put it to -name- file");
                print("2 get traffic features each 2 seconds from switches put it to -name- file");
                print("3 start firewall in RBFNetwork algorithm");
                print("4 start firewall in vote algorithm");
                print("5 stop firewall");
                break;
            case 1:
                executes(service, option);
                results(service.putArffFile(name));
                break;
            case 2:
                executes(service, option);
                results(service.putArffFile(name));
                break;
            case 3:
                executes(service);
                break;
            case 4:
                executes(service);
                break;
            case 5:
                schedule.shutdown();
                schedule = new ScheduledThreadPoolExecutor(1);
                break;
            default :
                print("please select 1 ~ 5 options");
                break;
        }
    }

    public void results(boolean value) {
        if (value) {
            print(String.format("%s is done", name));
        } else {
            print("there is no traffic");
        }
    }

    public void executes(FlowMonitoringTool service, int choose) {
        FlowMonitoringTool.Schedule job = service.buildSchedule(choose);
        schedule.scheduleAtFixedRate(job, 0, DEFAULT_MONITORTIME, TimeUnit.SECONDS);
        try {
            Thread.sleep(DEFAULT_LASTTIME);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        schedule.shutdown();
        schedule = new ScheduledThreadPoolExecutor(1);
    }

    public void executes(FlowMonitoringTool service) {
        FlowMonitoringTool.Schedule job1 = service.buildSchedule(2);
        FlowMonitoringTool.Schedule job2 = service.buildSchedule(option);
        schedule.scheduleAtFixedRate(job1, 0, DEFAULT_MONITORTIME, TimeUnit.SECONDS);
        schedule.scheduleAtFixedRate(job2, DEFAULT_FIWARETIME, DEFAULT_FIWARETIME, TimeUnit.SECONDS);
    }

}

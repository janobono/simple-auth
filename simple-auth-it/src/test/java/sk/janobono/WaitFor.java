package sk.janobono;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

public class WaitFor {

    public static void waitForCounter(AtomicInteger counter, int result, int timeoutInMinutes) {
        long startTimeMillis = System.currentTimeMillis();
        do {
            if (System.currentTimeMillis() - startTimeMillis > TimeUnit.MINUTES.toMillis(timeoutInMinutes)) {
                throw new RuntimeException("Timeout");
            }
        } while (counter.get() != result);
    }

    @FunctionalInterface
    public interface Tst {
        boolean ok();
    }

    public static void waitForTst(int timeoutInMinutes, Tst tst) {
        long startTimeMillis = System.currentTimeMillis();
        do {
            if (System.currentTimeMillis() - startTimeMillis > TimeUnit.MINUTES.toMillis(timeoutInMinutes)) {
                throw new RuntimeException("Timeout");
            }
        } while (!tst.ok());
    }
}

package sk.janobono.simple;

import org.mockito.Mockito;
import sk.janobono.simple.business.model.mail.MailData;
import sk.janobono.simple.business.service.MailService;

import java.util.concurrent.atomic.AtomicReference;

public class TestMail {

    private final AtomicReference<MailData> mail = new AtomicReference<>();

    public void mock(final MailService mailService) {
        mail.set(null);
        Mockito.doAnswer(answer -> {
                    final MailData data = answer.getArgument(0);
                    mail.set(data);
                    return null;
                })
                .when(mailService).sendEmail(Mockito.any(MailData.class));
    }

    public MailData getMail() {
        return mail.get();
    }
}

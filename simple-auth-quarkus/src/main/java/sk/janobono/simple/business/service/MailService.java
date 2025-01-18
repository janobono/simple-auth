package sk.janobono.simple.business.service;

import io.quarkus.mailer.Mail;
import io.quarkus.mailer.Mailer;
import io.quarkus.qute.Template;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.util.Collection;
import java.util.Map;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.jboss.logging.Logger;
import sk.janobono.simple.business.model.mail.MailContentData;
import sk.janobono.simple.business.model.mail.MailData;
import sk.janobono.simple.business.model.mail.MailLinkData;

@RequiredArgsConstructor
@ApplicationScoped
public class MailService {

    private final Logger log;
    private final Template email;

    private Mailer mailer;

    @Inject
    public void setMailer(final Mailer mailer) {
        this.mailer = mailer;
    }

    public void sendEmail(final MailData mailData) {
        try {
            final Mail mail = new Mail();

            mail.setFrom(mailData.from());

            if (Optional.ofNullable(mailData.replyTo()).filter(s -> !s.isBlank()).isPresent()) {
                mail.setReplyTo(mailData.replyTo());
            }

            Optional.ofNullable(mailData.recipients()).stream()
                .flatMap(Collection::stream)
                .forEach(mail::addTo);

            Optional.ofNullable(mailData.cc()).stream()
                .flatMap(Collection::stream)
                .forEach(mail::addCc);

            mail.setSubject(mailData.subject());

            mail.setHtml(renderEmail(mailData.content()));

            Optional.ofNullable(mailData.attachments())
                .map(Map::entrySet).stream()
                .flatMap(Collection::stream)
                .forEach(attachment -> {
                    mail.addAttachment(attachment.getKey(), attachment.getValue(), "application/octet-stream");
                });

            mailer.send(mail);
        } finally {
            Optional.ofNullable(mailData.attachments()).map(Map::values).stream().flatMap(Collection::stream)
                .forEach(attachment -> {
                    final boolean deleted = attachment.delete();
                    if (!deleted) {
                        log.warn("Attachment not deleted %s".formatted(attachment.getName()));
                    }
                });
        }
    }

    private String renderEmail(final MailContentData mailContentData) {
        return this.email
            .data("title", mailContentData.title())
            .data("lines", mailContentData.lines())
            .data("isLink", Optional.ofNullable(mailContentData.mailLink()).isPresent())
            .data("linkHref", Optional.ofNullable(mailContentData.mailLink()).map(MailLinkData::href).orElse(""))
            .data("linkText", Optional.ofNullable(mailContentData.mailLink()).map(MailLinkData::text).orElse(""))
            .render();
    }
}

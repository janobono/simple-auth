package sk.janobono.simple.business.service;

import jakarta.mail.Message;
import jakarta.mail.MessagingException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.mail.javamail.MimeMessagePreparator;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;
import org.thymeleaf.context.IContext;
import sk.janobono.simple.business.model.mail.MailContentData;
import sk.janobono.simple.business.model.mail.MailData;
import sk.janobono.simple.business.model.mail.MailLinkData;

import java.util.Collection;
import java.util.Map;
import java.util.Optional;

@Slf4j
@RequiredArgsConstructor
@Service
public class MailService {

    private final JavaMailSender javaMailSender;
    private final TemplateEngine templateEngine;

    @Async
    public void sendEmail(final MailData mailData) {
        try {
            final MimeMessagePreparator mimeMessagePreparator = mimeMessage -> {
                final MimeMessageHelper messageHelper = new MimeMessageHelper(
                        mimeMessage,
                        Optional.ofNullable(mailData.attachments()).map(att -> !att.isEmpty()).orElse(false)
                );

                messageHelper.setFrom(mailData.from());

                if (Optional.ofNullable(mailData.replyTo()).filter(s -> !s.isBlank()).isPresent()) {
                    messageHelper.setReplyTo(mailData.replyTo());
                }

                Optional.ofNullable(mailData.recipients()).stream().flatMap(Collection::stream).forEach(recipient -> {
                    try {
                        mimeMessage.addRecipients(Message.RecipientType.TO, recipient);
                    } catch (final MessagingException e) {
                        throw new RuntimeException(e);
                    }
                });

                Optional.ofNullable(mailData.cc()).stream().flatMap(Collection::stream).forEach(cc -> {
                    try {
                        mimeMessage.addRecipients(Message.RecipientType.CC, cc);
                    } catch (final MessagingException e) {
                        throw new RuntimeException(e);
                    }
                });

                messageHelper.setSubject(mailData.subject());
                messageHelper.setText(format(mailData.content()), true);

                Optional.ofNullable(mailData.attachments())
                        .map(Map::entrySet).stream()
                        .flatMap(Collection::stream)
                        .forEach(attachment -> {
                            try {
                                messageHelper.addAttachment(attachment.getKey(), attachment.getValue());
                            } catch (final MessagingException e) {
                                throw new RuntimeException(e);
                            }
                        });
            };
            javaMailSender.send(mimeMessagePreparator);
        } finally {
            Optional.ofNullable(mailData.attachments()).map(Map::values).stream().flatMap(Collection::stream)
                    .forEach(attachment -> {
                        final boolean deleted = attachment.delete();
                        if (!deleted) {
                            log.warn("Attachment not deleted {}", attachment);
                        }
                    });
        }
    }

    private String format(final MailContentData mailContentData) {
        return templateEngine.process("MailTemplate", getContext(mailContentData));
    }

    private IContext getContext(final MailContentData mailContentData) {
        final Context context = new Context();
        context.setVariable("title", mailContentData.title());
        context.setVariable("lines", mailContentData.lines());
        context.setVariable("isLink", Optional.ofNullable(mailContentData.mailLink()).isPresent());
        context.setVariable("linkHref", Optional.ofNullable(mailContentData.mailLink()).map(MailLinkData::href).orElse(""));
        context.setVariable("linkText", Optional.ofNullable(mailContentData.mailLink()).map(MailLinkData::text).orElse(""));
        return context;
    }
}

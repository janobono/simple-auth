package sk.janobono.simple.business.model.mail;

import lombok.Builder;

import java.io.File;
import java.util.List;
import java.util.Map;

@Builder
public record MailData(
        String from,
        String replyTo,
        List<String> recipients,
        List<String> cc,
        String subject,
        MailContentData content,
        Map<String, File> attachments
) {
}

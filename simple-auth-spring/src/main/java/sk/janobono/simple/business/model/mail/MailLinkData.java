package sk.janobono.simple.business.model.mail;

import lombok.Builder;

@Builder
public record MailLinkData(String href, String text) {

}

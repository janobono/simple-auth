package sk.janobono.simple.business.model.mail;

import java.util.List;
import lombok.Builder;

@Builder
public record MailContentData(String title, List<String> lines, MailLinkData mailLink) {

}

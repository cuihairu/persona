import SafariServices
import os.log

class SafariWebExtensionHandler: NSObject, NSExtensionRequestHandling {
    func beginRequest(with context: NSExtensionContext) {
        guard let message = context.inputItems.first as? NSExtensionItem else {
            context.completeRequest(returningItems: nil, completionHandler: nil)
            return
        }

        os_log("Received message from Safari WebExtension: %{public}@", message)
        context.completeRequest(returningItems: [message], completionHandler: nil)
    }
}

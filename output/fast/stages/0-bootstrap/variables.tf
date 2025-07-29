variable "alert_config" {
  description = "Configuration for alert channels"
  type = object({
    notification_channels = list(string)
  })
  default = {
    notification_channels = []
  }
}

import { IconBolt } from "@tabler/icons-react";
import {
  Item,
  ItemActions,
  ItemContent,
  ItemDescription,
  ItemMedia,
  ItemTitle,
} from "@/components/ui/item";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  parseSendMode,
  SEND_MODES,
  type SendMode,
  useSendMode,
} from "@/lib/settings/send-mode";

const SEND_MODE_NAMES: Record<SendMode, string> = {
  queue: "Queue (wait when busy)",
  instant: "Instant (interrupt & send)",
};

/**
 * Whether a message typed while a Bot is working waits in the queue or interrupts and sends now.
 * Kept in browser storage so switching conversations and reloads preserve the choice immediately.
 */
export function SendModeRow() {
  const [sendMode, setSendMode] = useSendMode();

  return (
    <Item size="sm">
      <ItemMedia variant="icon">
        <IconBolt />
      </ItemMedia>
      <ItemContent>
        <ItemTitle>Send mode while busy</ItemTitle>
        <ItemDescription>
          Choose whether sending while a Bot is working queues behind it or
          interrupts and sends immediately.
        </ItemDescription>
      </ItemContent>
      <ItemActions>
        <Select
          value={sendMode}
          onValueChange={(value) => {
            if (value === "queue" || value === "instant") {
              setSendMode(parseSendMode(value));
            }
          }}
        >
          <SelectTrigger aria-label="Send mode while busy">
            <SelectValue>{SEND_MODE_NAMES[sendMode]}</SelectValue>
          </SelectTrigger>
          <SelectContent align="end" alignItemWithTrigger={false}>
            {SEND_MODES.map((mode) => (
              <SelectItem key={mode} value={mode}>
                {SEND_MODE_NAMES[mode]}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </ItemActions>
    </Item>
  );
}

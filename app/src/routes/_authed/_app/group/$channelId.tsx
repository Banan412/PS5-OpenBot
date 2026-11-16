import { IconSettings } from "@tabler/icons-react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { z } from "zod";
import { AgentProfile } from "@/components/agents/agent-profile";
import { ConversationApprovals } from "@/components/approvals/inline-approval";
import { BotPausedBanner } from "@/components/bot-profile/pause-banner";
import { ChannelAvatar } from "@/components/channels/avatar";
import { ConversationActions } from "@/components/channels/conversation-actions";
import { GroupChat } from "@/components/channels/group-chat";
import { GroupPeopleButton } from "@/components/channels/group-people";
import { ComputerChatControls } from "@/components/computer/computer-controls";
import { ComputerViewPanel } from "@/components/computer/computer-panel";
import { DetailPanel } from "@/components/layout/detail-panel";
import { SidebarToggle } from "@/components/layout/sidebar-toggle";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { agentListQueryOptions } from "@/lib/agents/queries";
import { updateConversation } from "@/lib/api/generated/conversations/conversations";
import { idempotencyKey, organizationId } from "@/lib/api/request";
import { useMarkOpenChannelRead } from "@/lib/channels/mark-read";
import { channelKeys, channelQueryOptions } from "@/lib/channels/queries";
import { useOpenComputerOnRequest } from "@/lib/computers/panel-view";
import { useNoBotComputers } from "@/lib/deployment/queries";
import { groupQueryOptions } from "@/lib/groups";

const groupSearchSchema = z.object({
  settings: z.boolean().optional(),
  watch: z.boolean().optional(),
  bot: z.string().optional(),
});

const SCREEN_PANEL_WIDTH = 400;

/** A conversation with several Bots, with Computer view, Settings, People, Approvals, Schedules & Files. */
export const Route = createFileRoute("/_authed/_app/group/$channelId")({
  validateSearch: groupSearchSchema,
  component: RouteComponent,
});

function GroupBotSwitcher({
  bots,
  selectedId,
  onSelect,
}: {
  bots: readonly { id: string; name: string }[];
  selectedId: string;
  onSelect: (id: string) => void;
}) {
  if (bots.length <= 1) return null;
  return (
    <div className="flex flex-wrap gap-1.5 border-b border-border px-4 py-2.5">
      {bots.map((bot) => {
        const active = bot.id === selectedId;
        return (
          <button
            key={bot.id}
            type="button"
            onClick={() => onSelect(bot.id)}
            className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-medium transition-colors ${
              active
                ? "border-primary bg-primary text-primary-foreground"
                : "border-border bg-muted/40 text-foreground hover:bg-muted"
            }`}
          >
            <ChannelAvatar participantIds={[bot.id]} size={14} />
            <span className="max-w-32 truncate">{bot.name || bot.id}</span>
          </button>
        );
      })}
    </div>
  );
}

function GroupSettingsDetail({
  channelId,
  initialTitle,
  bots,
  selectedBotId,
  onSelectBot,
  leave,
}: {
  channelId: string;
  initialTitle: string;
  bots: readonly { id: string; name: string }[];
  selectedBotId: string | undefined;
  onSelectBot: (id: string) => void;
  leave: () => Promise<unknown>;
}) {
  const queryClient = useQueryClient();
  const [title, setTitle] = useState(initialTitle);
  const [savedNotice, setSavedNotice] = useState(false);

  useEffect(() => {
    setTitle(initialTitle);
  }, [initialTitle]);

  const rename = useMutation({
    mutationFn: async (nextTitle: string) => {
      await updateConversation(
        organizationId(),
        channelId,
        { title: nextTitle.trim() || null },
        { "Idempotency-Key": idempotencyKey() },
      );
    },
    onSuccess: async () => {
      setSavedNotice(true);
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: channelKeys.all }),
        queryClient.invalidateQueries({
          queryKey: channelKeys.detail(channelId),
        }),
      ]);
      setTimeout(() => setSavedNotice(false), 2000);
    },
  });

  return (
    <div className="flex flex-col gap-5 pb-6">
      <section className="px-4 pt-4">
        <h2 className="mb-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">
          Group name
        </h2>
        <form
          className="flex items-center gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            rename.mutate(title);
          }}
        >
          <Input
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            placeholder="Group name"
            className="h-8 text-sm"
            maxLength={80}
          />
          <Button
            type="submit"
            size="sm"
            variant="outline"
            disabled={rename.isPending}
          >
            {rename.isPending ? "Saving…" : "Save"}
          </Button>
        </form>
        {savedNotice ? (
          <p className="mt-1 text-xs text-muted-foreground" role="status">
            Saved.
          </p>
        ) : null}
        {rename.error ? (
          <p className="mt-1 text-xs text-destructive" role="alert">
            Couldn't update group name.
          </p>
        ) : null}
      </section>

      {selectedBotId ? (
        <section>
          <div className="px-4 pb-1">
            <h2 className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
              Bots in this group
            </h2>
          </div>
          <GroupBotSwitcher
            bots={bots}
            selectedId={selectedBotId}
            onSelect={onSelectBot}
          />
          <AgentProfile
            agentId={selectedBotId}
            footer={
              <ConversationActions channelId={channelId} leave={leave} />
            }
          />
        </section>
      ) : (
        <div className="px-4">
          <ConversationActions channelId={channelId} leave={leave} />
        </div>
      )}
    </div>
  );
}

function RouteComponent() {
  const { channelId } = Route.useParams();
  const { settings, watch, bot } = Route.useSearch();
  const navigate = Route.useNavigate();
  const channel = useQuery(channelQueryOptions(channelId));
  const group = useQuery(groupQueryOptions(channelId));
  const allAgents = useQuery(agentListQueryOptions()).data;
  const noComputers = useNoBotComputers() === true;
  useMarkOpenChannelRead(channelId);

  const agentIds = channel.data?.agentIds ?? [];
  const groupBots: { id: string; name: string }[] = agentIds.map((id) => ({
    id,
    name:
      group.data?.bots.find((b) => b.id === id)?.name ??
      allAgents?.find((a) => a.id === id)?.name ??
      id,
  }));

  // Default to the active running bot in the group, else explicit `?bot=`, else first bot.
  const activeRunningBot = group.data?.messages
    .slice()
    .reverse()
    .find(
      (m) =>
        m.agentId !== null &&
        (m.status === "running" || m.status === "queued"),
    )?.agentId;
  const selectedBotId =
    (bot && agentIds.includes(bot) ? bot : undefined) ??
    (activeRunningBot && agentIds.includes(activeRunningBot)
      ? activeRunningBot
      : undefined) ??
    agentIds[0];
  const selectedBotName = groupBots.find((b) => b.id === selectedBotId)?.name;

  const isSettingsOpen = settings === true;
  const isWatching = watch === true;

  const show = (next: "settings" | "watch" | null, botId?: string) =>
    navigate({
      search: (previous) => ({
        ...previous,
        settings: next === "settings" ? true : undefined,
        watch: next === "watch" ? true : undefined,
        ...(botId !== undefined ? { bot: botId } : {}),
      }),
    });

  useOpenComputerOnRequest(selectedBotId, () => show("watch"));

  return (
    <DetailPanel
      onClose={() => show(null)}
      open={(isSettingsOpen || isWatching) && agentIds.length > 0}
      detailWidth={isWatching ? SCREEN_PANEL_WIDTH : undefined}
      title={isWatching ? "Computer" : "Group settings"}
      waiting={
        channel.data ? (
          <ConversationApprovals threadId={channel.data.threadId} />
        ) : null
      }
      detail={
        selectedBotId === undefined ? null : isWatching ? (
          <div className="flex flex-col">
            <GroupBotSwitcher
              bots={groupBots}
              selectedId={selectedBotId}
              onSelect={(id) => show("watch", id)}
            />
            <ComputerViewPanel agentId={selectedBotId} name={selectedBotName} />
          </div>
        ) : (
          <GroupSettingsDetail
            channelId={channelId}
            initialTitle={channel.data?.summary ?? channel.data?.name ?? ""}
            bots={groupBots}
            selectedBotId={selectedBotId}
            onSelectBot={(id) => show("settings", id)}
            leave={() => navigate({ to: "/" })}
          />
        )
      }
    >
      <div className="flex h-full min-h-0 flex-col">
        <div
          className="sticky top-0 flex min-h-12 flex-row items-center gap-1.5 border-b border-border px-3 py-2"
          data-slot="conversation-header"
        >
          <SidebarToggle />
          <ChannelAvatar participantIds={agentIds} size={22} />
          <span className="min-w-0 truncate text-sm tracking-tight">
            {channel.data?.summary || channel.data?.name || "Group"}
          </span>
          <div className="ml-auto flex flex-row items-center gap-1.5">
            <GroupPeopleButton channelId={channelId} />
            <ComputerChatControls
              computerId={selectedBotId}
              noComputers={noComputers}
              open={isWatching}
              onOpenChange={(open) => show(open ? "watch" : null)}
            />
            <Button
              aria-label="Group settings"
              aria-pressed={isSettingsOpen}
              className={isSettingsOpen ? "bg-foreground/5" : undefined}
              disabled={agentIds.length === 0}
              onClick={() => show(isSettingsOpen ? null : "settings")}
              variant="ghost"
              size="icon"
            >
              <IconSettings className="size-4.5" />
            </Button>
          </div>
        </div>
        {agentIds.map((agentId) => (
          <BotPausedBanner agentId={agentId} key={agentId} />
        ))}
        {/* Remounted per channel so one group's transcript never flashes in another. */}
        <GroupChat channelId={channelId} key={channelId} />
      </div>
    </DetailPanel>
  );
}

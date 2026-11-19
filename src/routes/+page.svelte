<script lang="ts">
  import { onMount } from "svelte";
  import { invoke } from "@tauri-apps/api/core";
  import {
    Activity,
    ArrowUpRight,
    Check,
    CircleHelp,
    Clock3,
    Command,
    ExternalLink,
    Globe2,
    LockKeyhole,
    Monitor,
    Plus,
    Router,
    Search,
    Shield,
    ShieldAlert,
    ShieldCheck,
    Trash2,
    Wifi,
    X,
  } from "@lucide/svelte";
  import { openUrl } from "@tauri-apps/plugin-opener";

  type Device = {
    name: string;
    mac: string;
    ip: string;
    last_connection: string | null;
  };
  type Rule = {
    id: number;
    domain: string;
    domains: string[];
    deviceLabel: string;
    deviceMac: string;
    enabled: boolean;
    routerAccepted?: boolean;
    blockAll?: boolean;
    schedule?: { days: number[]; start: string; end: string };
  };
  type RouterLoginResult = { address: string; title: string | null };
  type RouterRule = {
    inst_id: string;
    name: string;
    enabled: boolean;
    mode: string;
    device_mac: string | null;
    domains: string[];
    schedule: string | null;
  };
  type RouterProbeResult = { status: number; title: string | null };
  const DAY_NAMES = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
  const YOUTUBE_APP_DOMAINS = [
    "youtube.com",
    "youtubei.googleapis.com",
    "googlevideo.com",
    "ytimg.com",
    "youtube.googleapis.com",
  ];
  let devices = $state<Device[]>([]);
  let rules = $state<Rule[]>([]);
  let view = $state("Overview");
  let search = $state("");
  let modalOpen = $state(false);
  let domain = $state("");
  let blockAllInternet = $state(false);
  let scheduleCustom = $state(false);
  let scheduleDays = $state<number[]>([1, 2, 3, 4, 5]);
  let scheduleStart = $state("21:00");
  let scheduleEnd = $state("23:59");
  let deviceLabel = $state("");
  let deviceMac = $state("");
  let notice = $state("");
  let routerAddress = $state("192.168.1.1");
  let routerProbe = $state<RouterProbeResult | null>(null);
  let routerProbeError = $state("");
  let probingRouter = $state(false);
  let routerUsername = $state("");
  let routerPassword = $state("");
  let routerLogin = $state<RouterLoginResult | null>(null);
  let routerLoginError = $state("");
  let loggingIn = $state(false);
  let isDesktopApp = $state(false);
  let applyingRuleId = $state<number | null>(null);
  let routerRules = $state<RouterRule[]>([]);
  let routerRulesLoading = $state(false);
  let routerRulesError = $state("");
  let deletingRouterRuleId = $state<string | null>(null);
  let devicesLoading = $state(false);
  let devicesError = $state("");
  let deviceAgeFilter = $state("all");
  function wasSeenWithin(device: Device, windowMinutes: string) {
    if (windowMinutes === "all") return true;
    if (!device.last_connection) return false;
    const parsed = new Date(device.last_connection.trim().replace(" ", "T"));
    if (Number.isNaN(parsed.getTime())) return false;
    const ageMinutes = (Date.now() - parsed.getTime()) / 60_000;
    return ageMinutes >= -2 && ageMinutes <= Number(windowMinutes);
  }
  let visibleDevices = $derived(
    devices.filter(
      (device) =>
        `${device.name} ${device.ip} ${device.mac}`
          .toLowerCase()
          .includes(search.toLowerCase()) &&
        wasSeenWithin(device, deviceAgeFilter),
    ),
  );
  let visibleRules = $derived(
    rules.filter((rule) =>
      `${rule.blockAll ? "all internet" : rule.domains.join(" ")} ${rule.deviceLabel} ${rule.deviceMac}`
        .toLowerCase()
        .includes(search.toLowerCase()),
    ),
  );

  onMount(() => {
    isDesktopApp = "__TAURI_INTERNALS__" in window;
    try {
      const saved = localStorage.getItem("router-warden-rules");
      if (saved) {
        const stored = JSON.parse(saved) as Array<Partial<Rule>>;
        rules = stored.map((rule) => {
          const domains = rule.blockAll
            ? []
            : rule.domains?.length
              ? rule.domains
              : [rule.domain ?? ""];
          return {
            id: rule.id ?? Date.now(),
            domain: rule.domain ?? domains[0] ?? "",
            domains,
            blockAll: rule.blockAll ?? false,
            schedule: rule.schedule,
            deviceLabel: rule.deviceLabel ?? "Device",
            deviceMac: rule.deviceMac ?? "",
            enabled: rule.enabled ?? true,
            routerAccepted: rule.routerAccepted ?? false,
          };
        });
      }
    } catch {
      localStorage.removeItem("router-warden-rules");
    }
    routerAddress =
      localStorage.getItem("router-warden-address") ?? "192.168.1.1";
  });

  function saveRules() {
    localStorage.setItem("router-warden-rules", JSON.stringify(rules));
  }

  $effect(() => {
    if (view === "Rules" && routerLogin && isDesktopApp) void loadRouterRules();
  });

  $effect(() => {
    if (!routerLogin || !isDesktopApp) return;
    const timer = window.setInterval(async () => {
      try {
        await invoke("keep_router_session_alive", { address: routerAddress });
      } catch {
        routerLogin = null;
        flash("Router session expired. Sign in again.");
      }
    }, 60_000);
    return () => window.clearInterval(timer);
  });

  function scheduleSummary(rule: Rule) {
    if (!rule.schedule) return "all day, every day";
    const days =
      rule.schedule.days.length === 7
        ? "Every day"
        : rule.schedule.days.map((day) => DAY_NAMES[day]).join(", ");
    return `${days} ${rule.schedule.start}\u2013${rule.schedule.end}`;
  }

  function domainSummary(rule: Rule) {
    if (rule.blockAll) return "All internet access";
    return rule.domains.length > 1
      ? `${rule.domains[0]} +${rule.domains.length - 1}`
      : rule.domains[0];
  }

  function flash(message: string) {
    notice = message;
    window.setTimeout(() => (notice = ""), 3500);
  }

  function addRule(event: SubmitEvent) {
    event.preventDefault();
    const cleanDomains = [
      ...new Set(
        domain
          .split(/[\s,;]+/)
          .map((entry) =>
            entry
              .trim()
              .toLowerCase()
              .replace(/^https?:\/\//, "")
              .replace(/\/$/, ""),
          )
          .filter(Boolean),
      ),
    ];
    const isValidDomain = (value: string) =>
      value.length <= 253 &&
      value
        .split(".")
        .every(
          (label) =>
            label.length > 0 &&
            label.length <= 63 &&
            /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label),
        ) &&
      value.includes(".");
    if (
      !blockAllInternet &&
      (cleanDomains.length === 0 ||
        cleanDomains.length > 5 ||
        cleanDomains.some((entry) => !isValidDomain(entry)))
    ) {
      flash("Enter 1 to 5 plain domains, one per line");
      return;
    }
    const cleanMac = deviceMac.trim().toUpperCase();
    if (!/^([0-9A-F]{2}:){5}[0-9A-F]{2}$/.test(cleanMac)) {
      flash(
        "Enter the target device's MAC address from the router device list",
      );
      return;
    }
    if (!deviceLabel.trim()) {
      flash("Enter a label for this device");
      return;
    }
    if (scheduleCustom) {
      if (scheduleDays.length === 0) {
        flash("Choose at least one day for the schedule");
        return;
      }
      if (!scheduleStart || !scheduleEnd || scheduleEnd <= scheduleStart) {
        flash("The end time must be after the start time on the same day");
        return;
      }
    }
    rules = [
      {
        id: Date.now(),
        domain: blockAllInternet ? "" : cleanDomains[0],
        domains: blockAllInternet ? [] : cleanDomains,
        blockAll: blockAllInternet,
        schedule: scheduleCustom
          ? {
              days: [...scheduleDays].sort(),
              start: scheduleStart,
              end: scheduleEnd,
            }
          : undefined,
        deviceLabel: deviceLabel.trim(),
        deviceMac: cleanMac,
        enabled: true,
        routerAccepted: false,
      },
      ...rules,
    ];
    saveRules();
    domain = "";
    blockAllInternet = false;
    scheduleCustom = false;
    scheduleDays = [1, 2, 3, 4, 5];
    scheduleStart = "21:00";
    scheduleEnd = "23:59";
    deviceLabel = "";
    deviceMac = "";
    modalOpen = false;
    flash(
      "Saved as a local preview. Apply it from Block rules after signing in.",
    );
  }

  async function applyRule(rule: Rule) {
    if (!isDesktopApp) {
      flash("Open the Router Warden desktop app to apply router rules");
      return;
    }
    if (!routerLogin) {
      flash("Sign in to the router before applying a rule");
      return;
    }
    const confirmed = window.confirm(
      `${
        rule.blockAll
          ? `Block ALL internet access for ${rule.deviceLabel} (${rule.deviceMac})`
          : `Apply a URL blacklist for ${rule.domains.join(", ")} to ${rule.deviceLabel} (${rule.deviceMac})`
      } — ${scheduleSummary(rule)}? ${rule.blockAll && !rule.schedule ? "The device will be offline until you delete this rule. " : ""}This changes router settings.`,
    );
    if (!confirmed) return;
    applyingRuleId = rule.id;
    try {
      const result = await invoke<{
        status: number;
        confirmed: boolean;
        error_code: string | null;
      }>(rule.blockAll ? "apply_internet_block" : "apply_url_blacklist", {
        address: routerAddress,
        deviceMac: rule.deviceMac,
        ...(rule.blockAll ? {} : { domains: rule.domains }),
        schedule: rule.schedule
          ? {
              days: rule.schedule.days,
              startHour: Number(rule.schedule.start.slice(0, 2)),
              startMin: Number(rule.schedule.start.slice(3, 5)),
              endHour: Number(rule.schedule.end.slice(0, 2)),
              endMin: Number(rule.schedule.end.slice(3, 5)),
            }
          : null,
      });
      if (result.confirmed) {
        rules = rules.map((item) =>
          item.id === rule.id ? { ...item, routerAccepted: true } : item,
        );
        saveRules();
        flash(
          `Router accepted the rule (HTTP ${result.status}). ${rule.blockAll ? "Verify the device is offline" : `Verify ${rule.domains.length} domain${rule.domains.length === 1 ? "" : "s"}`} in Parental Controls.`,
        );
      } else {
        flash(
          `Router did not confirm the rule (HTTP ${result.status}${result.error_code ? `, ${result.error_code}` : ", no success code"}). The rule remains retryable.`,
        );
      }
    } catch (error) {
      if (String(error).includes("session expired")) routerLogin = null;
      flash(`Rule was not confirmed: ${String(error)}`);
    } finally {
      applyingRuleId = null;
    }
  }

  async function loadRouterRules() {
    if (!isDesktopApp || !routerLogin) return;
    routerRulesLoading = true;
    routerRulesError = "";
    try {
      routerRules = await invoke<RouterRule[]>("list_router_rules", {
        address: routerAddress,
      });
    } catch (error) {
      routerRulesError = String(error);
      if (routerRulesError.includes("session expired")) routerLogin = null;
    } finally {
      routerRulesLoading = false;
    }
  }

  async function deleteRouterRule(rule: RouterRule) {
    if (!isDesktopApp || !routerLogin) {
      flash("Sign in to the router before deleting a rule");
      return;
    }
    const target = rule.device_mac ? ` for ${rule.device_mac}` : "";
    if (
      !window.confirm(
        `Delete router rule "${rule.name}"${target}? This changes router settings.`,
      )
    )
      return;
    deletingRouterRuleId = rule.inst_id;
    try {
      const result = await invoke<{
        status: number;
        confirmed: boolean;
        error_code: string | null;
      }>("delete_router_rule", {
        address: routerAddress,
        instId: rule.inst_id,
      });
      if (result.confirmed) {
        rules = rules.map((item) =>
          item.routerAccepted &&
          item.deviceMac.toLowerCase() === rule.device_mac?.toLowerCase() &&
          (rule.mode === "NotAllowed"
            ? item.blockAll
            : item.domains.some((domain) => rule.domains.includes(domain)))
            ? { ...item, routerAccepted: false }
            : item,
        );
        saveRules();
        flash(`Deleted "${rule.name}" from the router.`);
      } else {
        flash(
          `Router did not confirm the delete (HTTP ${result.status}${result.error_code ? `, ${result.error_code}` : ""}).`,
        );
      }
      await loadRouterRules();
    } catch (error) {
      if (String(error).includes("session expired")) routerLogin = null;
      flash(`Delete was not confirmed: ${String(error)}`);
    } finally {
      deletingRouterRuleId = null;
    }
  }

  function toggleRule(id: number) {
    rules = rules.map((rule) =>
      rule.id === id ? { ...rule, enabled: !rule.enabled } : rule,
    );
    saveRules();
  }

  function deleteRule(id: number) {
    rules = rules.filter((rule) => rule.id !== id);
    saveRules();
  }

  async function openRouter() {
    if (!isPrivateRouterAddress(routerAddress)) {
      flash("Enter a private LAN IPv4 address first");
      return;
    }
    const url = `http://${routerAddress.trim()}/`;
    if (isDesktopApp) await openUrl(url);
    else window.open(url, "_blank", "noopener,noreferrer");
  }

  function isPrivateRouterAddress(address: string) {
    const octets = address.trim().split(".").map(Number);
    if (
      octets.length !== 4 ||
      octets.some(
        (octet) => !Number.isInteger(octet) || octet < 0 || octet > 255,
      )
    )
      return false;
    return (
      octets[0] === 10 ||
      (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) ||
      (octets[0] === 192 && octets[1] === 168)
    );
  }

  async function testRouter(event: SubmitEvent) {
    event.preventDefault();
    if (!isDesktopApp) {
      routerProbeError =
        "Use the Router Warden desktop app to test the local router connection.";
      return;
    }
    probingRouter = true;
    routerProbe = null;
    routerProbeError = "";
    try {
      routerProbe = await invoke<RouterProbeResult>("probe_router", {
        address: routerAddress,
      });
      localStorage.setItem("router-warden-address", routerAddress.trim());
    } catch (error) {
      routerProbeError = String(error);
    } finally {
      probingRouter = false;
    }
  }

  async function connectRouter(event: SubmitEvent) {
    event.preventDefault();
    if (!isDesktopApp) {
      routerLoginError =
        "Use the Router Warden desktop app to sign in. No credentials were sent.";
      routerPassword = "";
      return;
    }
    loggingIn = true;
    routerLogin = null;
    routerLoginError = "";
    try {
      routerLogin = await invoke<RouterLoginResult>("connect_router", {
        address: routerAddress,
        username: routerUsername,
        password: routerPassword,
      });
      localStorage.setItem("router-warden-address", routerLogin.address);
      routerPassword = "";
      await refreshRouterDevices();
    } catch (error) {
      routerLoginError = String(error);
      routerPassword = "";
    } finally {
      loggingIn = false;
    }
  }

  async function disconnectRouter() {
    if (!isDesktopApp) {
      flash("Open the Router Warden desktop app to manage the router session");
      return;
    }
    try {
      await invoke("disconnect_router", { address: routerAddress });
      routerLogin = null;
      devices = [];
      devicesError = "";
      routerLoginError = "";
      flash("Router session cleared from memory");
    } catch (error) {
      routerLoginError = String(error);
    }
  }

  async function refreshRouterDevices() {
    if (!isDesktopApp) {
      devicesError =
        "Open the Router Warden desktop app to load live router devices.";
      return;
    }
    if (!routerLogin) return;
    devicesLoading = true;
    devicesError = "";
    try {
      devices = await invoke<Device[]>("list_router_devices", {
        address: routerAddress,
      });
    } catch (error) {
      devicesError = String(error);
    } finally {
      devicesLoading = false;
    }
  }
</script>

<svelte:head>
  <title>Router Warden</title>
  <meta
    name="description"
    content="Manage device-specific website block rules on your home network."
  />
</svelte:head>

<div class="flex min-h-screen bg-[#f3f5f1] text-[#20352a]">
  <aside
    class="flex w-[226px] shrink-0 flex-col bg-[#172d25] px-4 py-5 text-[#f4f5ec] max-[700px]:w-[60px] max-[700px]:items-center max-[700px]:px-2"
  >
    <div class="flex items-center gap-2.5 px-1">
      <span
        class="grid size-8 place-items-center rounded-lg bg-[#c3e5cb] text-[#183d30]"
        ><Shield size={19} /></span
      >
      <span class="font-display text-[17px] font-bold max-[700px]:hidden"
        >router<span class="text-[#b9d9bd]">warden</span></span
      >
      <span
        class="ml-auto rounded border border-[#456357] px-1 py-0.5 text-[8px] font-bold tracking-wider max-[700px]:hidden"
        >LOCAL</span
      >
    </div>
    <div
      class="mt-8 flex h-[54px] items-center gap-2.5 rounded-md border border-[#355346] bg-[#203b31] px-2.5 max-[700px]:size-10 max-[700px]:justify-center max-[700px]:px-0"
    >
      <Wifi size={17} class="shrink-0 text-[#bfe2c8]" /><span
        class="flex flex-1 flex-col max-[700px]:hidden"
        ><small class="text-[9px] font-bold tracking-[.1em] text-[#9bb7a7]"
          >NETWORK</small
        ><strong class="text-xs">Home network</strong></span
      >
    </div>
    <div
      class="mb-2 mt-8 px-2 text-[9px] font-bold tracking-[.12em] text-[#91aa9a] max-[700px]:hidden"
    >
      WORKSPACE
    </div>
    <nav class="flex flex-col gap-1" aria-label="Main navigation">
      <button
        class:!bg-[#c7e6ce]={view === "Overview"}
        class:!text-[#173e2f]={view === "Overview"}
        class="flex h-10 items-center gap-3 rounded px-2.5 text-left text-xs text-[#b5c7bb] hover:bg-[#213a30] max-[700px]:w-10 max-[700px]:justify-center max-[700px]:px-0"
        onclick={() => (view = "Overview")}
        ><Activity size={17} /><span class="max-[700px]:hidden">Overview</span
        ></button
      >
      <button
        class:!bg-[#c7e6ce]={view === "Devices"}
        class:!text-[#173e2f]={view === "Devices"}
        class="flex h-10 items-center gap-3 rounded px-2.5 text-left text-xs text-[#b5c7bb] hover:bg-[#213a30] max-[700px]:w-10 max-[700px]:justify-center max-[700px]:px-0"
        onclick={() => (view = "Devices")}
        ><Monitor size={17} /><span class="max-[700px]:hidden">Devices</span
        ></button
      >
      <button
        class:!bg-[#c7e6ce]={view === "Rules"}
        class:!text-[#173e2f]={view === "Rules"}
        class="flex h-10 items-center gap-3 rounded px-2.5 text-left text-xs text-[#b5c7bb] hover:bg-[#213a30] max-[700px]:w-10 max-[700px]:justify-center max-[700px]:px-0"
        onclick={() => (view = "Rules")}
        ><ShieldCheck size={17} /><span class="max-[700px]:hidden"
          >Block rules</span
        ><span class="ml-auto text-[10px] max-[700px]:hidden"
          >{rules.length.toString().padStart(2, "0")}</span
        ></button
      >
    </nav>
    <div
      class="mb-2 mt-8 px-2 text-[9px] font-bold tracking-[.12em] text-[#91aa9a] max-[700px]:hidden"
    >
      MANAGE
    </div>
    <button
      class:!bg-[#c7e6ce]={view === "Router"}
      class:!text-[#173e2f]={view === "Router"}
      class="flex h-10 items-center gap-3 rounded px-2.5 text-left text-xs text-[#b5c7bb] hover:bg-[#213a30] max-[700px]:w-10 max-[700px]:justify-center max-[700px]:px-0"
      onclick={() => (view = "Router")}
      ><Router size={17} /><span class="max-[700px]:hidden"
        >Router connection</span
      ></button
    >
    <div class="flex-1"></div>
    <div
      class="mb-3 flex gap-2 border-t border-[#365045] px-1 pt-3 text-[10px] leading-relaxed text-[#b5c7bb] max-[700px]:hidden"
    >
      <LockKeyhole size={15} class="mt-0.5 shrink-0 text-[#b7d9bf]" /><span
        >Preview rules stay on this computer until router sync is configured.</span
      >
    </div>
    <div
      class="flex w-full items-center gap-2 border-t border-[#365045] px-1 pt-3"
    >
      <span
        class="grid size-7 shrink-0 place-items-center rounded-full bg-[#e4a07f] font-display font-bold text-[#3e291d]"
        >P</span
      ><span class="flex flex-col text-[10px] max-[700px]:hidden"
        ><strong class="text-[#f1f3e9]">Local admin</strong><span
          class="text-[#9db2a4]"
          >{routerLogin
            ? "Router session active"
            : "Router not connected"}</span
        ></span
      >
    </div>
  </aside>

  <main class="min-w-0 flex-1">
    <header
      class="flex h-[62px] items-center justify-between border-b border-[#e3e8e1] bg-white/70 px-8 max-[700px]:px-4"
    >
      <div class="flex items-center gap-2.5 text-xs">
        <span class="text-[#8b9790]">Home network</span><span
          class="text-[#c3cbc4]">/</span
        ><strong>{view}</strong>
      </div>
      <div class="flex items-center gap-4">
        <span
          class="flex items-center gap-1.5 text-[9px] font-bold tracking-wider {routerLogin
            ? 'text-[#477753]'
            : 'text-[#97744a]'}"
          ><i
            class="size-1.5 rounded-full {routerLogin
              ? 'bg-[#5b9d68]'
              : 'bg-[#d8a246]'}"
          ></i>
          {routerLogin ? "ROUTER CONNECTED" : "LOCAL PREVIEW"}</span
        ><button
          class="grid size-8 place-items-center rounded border border-[#e2e7e0] bg-white text-[#66736b]"
          title="Router connection help"
          aria-label="Router connection help"
          onclick={() => (view = "Router")}><CircleHelp size={17} /></button
        >
      </div>
    </header>
    <div
      class="mx-auto max-w-[1400px] px-8 py-8 max-[700px]:px-4 max-[700px]:py-6"
    >
      {#if view === "Overview"}
        <div
          class="mb-5 flex items-end justify-between gap-4 max-[700px]:flex-col max-[700px]:items-start"
        >
          <div>
            <p
              class="mb-2 flex items-center gap-2 text-[9px] font-bold tracking-[.12em] text-[#63806e]"
            >
              <i class="h-0.5 w-5 bg-[#dc8f67]"></i> YOUR NETWORK, AT A GLANCE
            </p>
            <h1 class="font-display text-[29px] font-semibold leading-tight">
              Network overview<span class="text-[#d7825d]">.</span>
            </h1>
            <p class="mt-2 text-xs text-[#748178]">
              See what is connected and shape access, device by device.
            </p>
          </div>
          <button
            class="inline-flex h-9 items-center gap-2 rounded bg-[#245b43] px-3.5 text-[11px] font-bold text-white hover:bg-[#1b4b37]"
            onclick={() => (modalOpen = true)}
            ><Plus size={16} /> Add block rule</button
          >
        </div>
        <div
          class="mb-4 flex min-h-[58px] items-center gap-3 rounded border border-[#eed9bd] border-l-[3px] border-l-[#d99a56] bg-[#fcf8f0] px-3 py-2 max-[700px]:flex-wrap"
        >
          <span
            class="grid size-8 shrink-0 place-items-center rounded-full bg-[#f2e8d6] text-[#a46c32]"
            ><ShieldAlert size={18} /></span
          >
          <div class="flex-1">
            <strong class="block text-[11px] text-[#5d4b36]"
              >{routerLogin
                ? "Router session active"
                : "Router not connected"}</strong
            ><span class="text-[10px] text-[#87745b]"
              >{routerLogin
                ? "Rules are applied individually after confirmation."
                : "Sign in to load live devices. Rules stay local until applied."}</span
            >
          </div>
          <button
            class="inline-flex items-center gap-1 text-[10px] font-bold text-[#755733]"
            onclick={() => (view = "Router")}
            >{routerLogin ? "Manage" : "Set up"}
            <ArrowUpRight size={14} /></button
          >
        </div>
        <section
          class="mb-4 grid grid-cols-4 gap-3 max-[900px]:grid-cols-2 max-[440px]:grid-cols-1"
          aria-label="Network summary"
        >
          <article
            class="rounded-md border border-[#d9e9d9] bg-[#f0f7f0] p-3.5"
          >
            <div
              class="flex items-center justify-between text-[9px] font-bold tracking-wider text-[#849088]"
            >
              ROUTER-LISTED DEVICES <Wifi size={17} class="text-[#33744e]" />
            </div>
            <p class="mt-2 font-display text-2xl font-semibold">
              {devices.length.toString().padStart(2, "0")}
              <span class="font-sans text-[11px] text-[#7a887e]">devices</span>
            </p>
            <p class="mt-1 text-[9px] text-[#7d8b81]">
              {routerLogin
                ? "Includes remembered clients"
                : "Sign in to load devices"}
            </p>
          </article>
          <article class="rounded-md border border-[#e4e9e2] bg-white p-3.5">
            <div
              class="flex items-center justify-between text-[9px] font-bold tracking-wider text-[#849088]"
            >
              BLOCK RULES <ShieldCheck size={17} class="text-[#b4623b]" />
            </div>
            <p class="mt-2 font-display text-2xl font-semibold">
              {rules
                .filter((rule) => rule.enabled)
                .length.toString()
                .padStart(2, "0")}
              <span class="font-sans text-[11px] text-[#7a887e]">enabled</span>
            </p>
            <p class="mt-1 text-[9px] text-[#9ca69e]">Saved on this computer</p>
          </article>
          <article class="rounded-md border border-[#e4e9e2] bg-white p-3.5">
            <div
              class="flex items-center justify-between text-[9px] font-bold tracking-wider text-[#849088]"
            >
              NETWORK STATUS <Router size={17} class="text-[#427392]" />
            </div>
            <p
              class="mt-2 flex items-center gap-2 font-display text-lg font-semibold"
            >
              <i
                class="size-2 rounded-full {routerLogin
                  ? 'bg-[#5b9d68]'
                  : 'bg-[#d7865f]'}"
              ></i>
              {routerLogin
                ? "Signed in"
                : routerProbe
                  ? "Reachable"
                  : "Not signed in"}
            </p>
            <p class="mt-1 text-[9px] text-[#9ca69e]">ZTE F670L · V9.0</p>
          </article>
          <article
            class="rounded-md border border-[#f1e7d6] bg-[#fffaf2] p-3.5"
          >
            <div
              class="flex items-center justify-between text-[9px] font-bold tracking-wider text-[#849088]"
            >
              ROUTER RULES <Clock3 size={17} class="text-[#997c37]" />
            </div>
            <p class="mt-2 font-display text-lg font-semibold">
              {rules.filter((rule) => rule.routerAccepted).length} accepted
            </p>
            <p class="mt-1 text-[9px] text-[#9ca69e]">Verify in router UI</p>
          </article>
        </section>
        <div
          class="grid grid-cols-[1.25fr_.9fr] gap-4 max-[1000px]:grid-cols-1"
        >
          <section class="rounded-md border border-[#e4e9e2] bg-white p-4">
            <div class="flex items-center justify-between">
              <div>
                <p class="text-[8px] font-bold tracking-widest text-[#91a096]">
                  ROUTER INVENTORY
                </p>
                <h2 class="mt-1 font-display text-[17px] font-semibold">
                  Devices <span class="font-sans text-[10px] text-[#9aa69d]"
                    >{devices.length.toString().padStart(2, "0")}</span
                  >
                </h2>
              </div>
              <button
                class="text-[10px] font-bold text-[#3c7652]"
                onclick={() => (view = "Devices")}
                >View all <ArrowUpRight size={13} class="inline" /></button
              >
            </div>
            <div class="my-3 flex flex-wrap items-center gap-2">
              <div
                class="flex h-8 min-w-0 flex-1 items-center gap-2 rounded border border-[#e4e9e3] px-2"
              >
                <Search size={14} class="text-[#8b978e]" />
                <input
                  class="min-w-0 flex-1 border-0 bg-transparent text-[10px] outline-none"
                  placeholder="Search devices"
                  aria-label="Search devices"
                  bind:value={search}
                />
              </div>
              <label class="flex items-center gap-2 text-[9px] text-[#68766d]"
                >Seen within
                <select
                  class="h-8 rounded border border-[#e4e9e3] bg-white px-2 text-[10px]"
                  aria-label="Filter devices by last seen"
                  bind:value={deviceAgeFilter}
                >
                  <option value="5">5 min</option>
                  <option value="15">15 min</option>
                  <option value="60">1 hour</option>
                  <option value="all">All records</option>
                </select>
              </label>
            </div>
            <p class="mb-2 text-[9px] text-[#929d95]">
              Based on the router’s last-connection time; not a live online
              indicator.
            </p>
            {#each visibleDevices as device}
              <div
                class="flex min-h-14 items-center gap-2.5 border-b border-[#edf0ec]"
              >
                <span
                  class="grid size-8 shrink-0 place-items-center rounded-md bg-[#e1f0e4] text-[#43835b]"
                  ><Monitor size={17} /></span
                ><span class="min-w-0 flex-1"
                  ><strong class="block truncate text-[11px] font-semibold"
                    >{device.name}</strong
                  ><small class="text-[9px] text-[#929d95]"
                    >{device.ip} · {device.mac}{device.last_connection
                      ? ` · Last seen ${device.last_connection}`
                      : ""}</small
                  ></span
                ><button
                  class="text-[10px] text-[#4b7d58]"
                  onclick={() => {
                    deviceLabel = device.name;
                    deviceMac = device.mac;
                    modalOpen = true;
                  }}>Add rule</button
                >
              </div>
            {/each}
            {#if devicesLoading}<p class="py-5 text-xs text-[#748178]">
                Loading router devices...
              </p>{:else if devicesError}<p class="py-5 text-xs text-[#9a6842]">
                {devicesError}
              </p>{:else if visibleDevices.length === 0}<p
                class="py-5 text-xs text-[#8f9a91]"
              >
                {routerLogin
                  ? "No active devices were returned by the router."
                  : "Sign in to load connected router devices."}
              </p>{/if}
            <p class="pt-3 text-[9px] text-[#9aa39c]">
              Live router device list
            </p>
          </section>
          <section class="rounded-md border border-[#e4e9e2] bg-white p-4">
            <div class="flex items-center justify-between">
              <div>
                <p class="text-[8px] font-bold tracking-widest text-[#91a096]">
                  ACCESS CONTROL
                </p>
                <h2 class="mt-1 font-display text-[17px] font-semibold">
                  Website rules
                </h2>
              </div>
              <button
                class="text-[10px] font-bold text-[#3c7652]"
                onclick={() => (view = "Rules")}
                >Manage <ArrowUpRight size={13} class="inline" /></button
              >
            </div>
            {#if rules.length === 0}<div
                class="my-6 rounded bg-[#f5f7f3] p-4 text-center"
              >
                <Globe2 size={20} class="mx-auto mb-2 text-[#71836f]" />
                <p class="text-[11px] font-semibold">No preview rules yet</p>
                <p class="mt-1 text-[10px] text-[#8b978e]">
                  Create a device-specific website list.
                </p>
              </div>{:else}{#each visibleRules.slice(0, 5) as rule}<div
                  class="flex min-h-14 items-center gap-2.5 border-b border-[#edf0ec]"
                >
                  <span
                    class="grid size-8 place-items-center rounded-full bg-[#eff3eb] text-[#657a60]"
                    ><Globe2 size={16} /></span
                  ><span class="min-w-0 flex-1"
                    ><strong class="block truncate text-[11px] font-semibold"
                      >{domainSummary(rule)}</strong
                    ><small class="text-[9px] text-[#97a098]"
                      >{rule.deviceLabel}</small
                    ></span
                  ><span
                    class:!bg-[#e4f1e6]={rule.enabled}
                    class="rounded-full bg-[#f0f1ee] px-2 py-1 text-[9px] text-[#89938b]"
                    >{rule.routerAccepted
                      ? "Accepted"
                      : rule.enabled
                        ? "Preview"
                        : "Paused"}</span
                  >
                </div>{/each}{/if}
            <button
              class="mt-3 inline-flex items-center gap-1.5 text-[10px] font-bold text-[#4b7d58]"
              onclick={() => (modalOpen = true)}
              ><Plus size={14} /> Add website rule</button
            >
          </section>
        </div>
        <section
          class="mt-4 flex items-center gap-3 rounded-md border border-[#dfe9df] bg-[#edf5ec] p-3"
        >
          <Router size={19} class="shrink-0 text-[#4f7959]" /><span
            class="flex-1"
            ><strong class="block text-[10px] text-[#34563d]"
              >Per-device URL Black List supported</strong
            ><small class="text-[9px] text-[#6f8572]"
              >Devices load from the router after sign-in. Verify each submitted
              rule in Parental Controls.</small
            ></span
          ><button
            class="text-[9px] font-bold text-[#46714e]"
            onclick={() => (view = "Router")}
            >Details <ArrowUpRight size={13} class="inline" /></button
          >
        </section>
      {:else if view === "Devices"}
        <div
          class="mb-5 flex items-end justify-between gap-4 max-[700px]:flex-col max-[700px]:items-start"
        >
          <div>
            <p class="eyebrow">ROUTER DEVICE LIST</p>
            <h1 class="font-display text-[29px] font-semibold">
              Devices<span class="text-[#d7825d]">.</span>
            </h1>
            <p class="mt-2 text-xs text-[#748178]">
              Router records can remain after a device disconnects from Wi-Fi.
            </p>
          </div>
          <div class="flex gap-2">
            <button
              class="secondary-button"
              onclick={refreshRouterDevices}
              disabled={!routerLogin || devicesLoading}
              ><Wifi size={15} /> Refresh devices</button
            ><button class="secondary-button" onclick={openRouter}
              ><ExternalLink size={15} /> Open router admin</button
            >
          </div>
        </div>
        <section class="rounded-md border border-[#e4e9e2] bg-white p-4">
          <div class="mb-3 flex flex-wrap items-center justify-between gap-3">
            <h2 class="font-display text-lg font-semibold">
              Router device records
            </h2>
            <div class="flex flex-wrap items-center gap-2">
              <div
                class="flex h-8 items-center gap-2 rounded border border-[#e4e9e3] px-2"
              >
                <Search size={14} /><input
                  class="h-8 min-w-0 text-[10px] outline-none"
                  placeholder="Search devices"
                  aria-label="Search devices"
                  bind:value={search}
                />
              </div>
              <label class="flex items-center gap-2 text-[9px] text-[#68766d]"
                >Seen within
                <select
                  class="h-8 rounded border border-[#e4e9e3] bg-white px-2 text-[10px]"
                  aria-label="Filter devices by last seen"
                  bind:value={deviceAgeFilter}
                >
                  <option value="5">5 min</option>
                  <option value="15">15 min</option>
                  <option value="60">1 hour</option>
                  <option value="all">All records</option>
                </select>
              </label>
            </div>
          </div>
          <p class="mb-2 text-[9px] text-[#929d95]">
            This is a recent-connection heuristic, not a confirmed online
            status.
          </p>
          {#each visibleDevices as device}<div
              class="flex min-h-16 items-center gap-3 border-t border-[#edf0ec]"
            >
              <span
                class="grid size-9 place-items-center rounded bg-[#e1f0e4] text-[#43835b]"
                ><Monitor size={18} /></span
              ><span class="flex-1"
                ><strong class="block text-xs">{device.name}</strong><small
                  class="text-[10px] text-[#929d95]"
                  >{device.ip} · {device.mac}{device.last_connection
                    ? ` · Last seen ${device.last_connection}`
                    : " · Last seen unavailable"}</small
                ></span
              ><button
                class="secondary-button"
                onclick={() => {
                  deviceLabel = device.name;
                  deviceMac = device.mac;
                  modalOpen = true;
                }}>Add rule</button
              >
            </div>{/each}{#if devicesLoading}<p
              class="py-5 text-xs text-[#748178]"
            >
              Loading router device records...
            </p>{:else if devicesError}<p class="py-5 text-xs text-[#9a6842]">
              {devicesError}
            </p>{:else if visibleDevices.length === 0}<p
              class="py-8 text-center text-xs text-[#8f9a91]"
            >
              {routerLogin
                ? "The router returned no device records."
                : "Sign in to the router to load its device records."}
            </p>{/if}
        </section>
      {:else if view === "Rules"}
        <div
          class="mb-5 flex items-end justify-between gap-4 max-[700px]:flex-col max-[700px]:items-start"
        >
          <div>
            <p class="eyebrow">DEVICE-SPECIFIC FILTERS</p>
            <h1 class="font-display text-[29px] font-semibold">
              Block rules<span class="text-[#d7825d]">.</span>
            </h1>
            <p class="mt-2 text-xs text-[#748178]">
              Manage local preview rules by device.
            </p>
          </div>
          <button
            class="inline-flex h-9 items-center gap-2 rounded bg-[#245b43] px-3.5 text-[11px] font-bold text-white"
            onclick={() => (modalOpen = true)}
            ><Plus size={16} /> Add block rule</button
          >
        </div>
        <section class="rounded-md border border-[#e4e9e2] bg-white p-4">
          <div class="mb-4 flex items-center justify-between gap-3">
            <h2 class="font-display text-lg font-semibold">
              Website block list
            </h2>
            <div
              class="flex items-center gap-2 rounded border border-[#e4e9e3] px-2"
            >
              <Search size={14} /><input
                class="h-8 text-[10px] outline-none"
                placeholder="Search rules"
                aria-label="Search rules"
                bind:value={search}
              />
            </div>
          </div>
          {#if visibleRules.length === 0}<p
              class="py-8 text-center text-xs text-[#8f9a91]"
            >
              No rules yet. Add a domain to get started.
            </p>{:else}{#each visibleRules as rule}<div
                class="grid min-h-14 grid-cols-[minmax(0,1fr)_minmax(160px,.8fr)_auto_auto] items-center gap-3 border-t border-[#edf0ec] max-[700px]:grid-cols-[minmax(0,1fr)_auto]"
              >
                <span class="flex min-w-0 items-center gap-2"
                  ><Globe2 size={16} class="shrink-0 text-[#657a60]" /><strong
                    class="truncate text-[11px]"
                    title={rule.domains.join(", ")}
                    >{domainSummary(rule)}</strong
                  ></span
                ><span class="truncate text-[10px] text-[#66746a]"
                  >{rule.deviceLabel} · {rule.deviceMac} · {scheduleSummary(
                    rule,
                  )}</span
                >{#if rule.routerAccepted}<span
                    class="text-[9px] font-semibold text-[#4b7954]"
                    >Accepted · verify in router</span
                  ><button
                    class="p-2 text-[#9aa39c] hover:text-[#b35c43]"
                    aria-label="Remove local record {domainSummary(rule)}"
                    title="Remove local record (does not change the router)"
                    onclick={() => deleteRule(rule.id)}
                    ><Trash2 size={15} /></button
                  >{:else}<button
                    class="rounded border border-[#dce5dc] px-2 py-2 text-[9px] font-bold text-[#456a4a] disabled:opacity-50"
                    disabled={!routerLogin ||
                      applyingRuleId === rule.id ||
                      !rule.enabled}
                    onclick={() => applyRule(rule)}
                    >{applyingRuleId === rule.id
                      ? "Applying..."
                      : routerLogin
                        ? "Apply to router"
                        : "Sign in first"}</button
                  ><button
                    class:!text-[#46805a]={rule.enabled}
                    class="text-[10px] text-[#89938b]"
                    onclick={() => toggleRule(rule.id)}
                    >{rule.enabled ? "Preview on" : "Preview off"}</button
                  ><button
                    class="p-2 text-[#9aa39c] hover:text-[#b35c43]"
                    aria-label="Delete {domainSummary(rule)}"
                    title="Delete local rule"
                    onclick={() => deleteRule(rule.id)}
                    ><Trash2 size={15} /></button
                  >{/if}
              </div>{/each}{/if}
          <p class="pt-4 text-[9px] text-[#9aa39c]">
            Router writes require sign-in and explicit confirmation. Verify each
            submitted rule in the router UI.
          </p>
        </section>
        <section class="mt-4 rounded-md border border-[#e4e9e2] bg-white p-4">
          <div class="mb-3 flex items-center justify-between gap-3">
            <h2 class="font-display text-lg font-semibold">
              Rules on the router
            </h2>
            <button
              class="secondary-button"
              onclick={loadRouterRules}
              disabled={!routerLogin || routerRulesLoading}
              >{routerRulesLoading
                ? "Loading..."
                : "Refresh from router"}</button
            >
          </div>
          {#each routerRules as routerRule (routerRule.inst_id)}<div
              class="grid min-h-14 grid-cols-[minmax(0,1fr)_minmax(160px,.8fr)_auto] items-center gap-3 border-t border-[#edf0ec] max-[700px]:grid-cols-[minmax(0,1fr)_auto]"
            >
              <span class="min-w-0"
                ><strong class="block truncate text-[11px]"
                  >{routerRule.name}{routerRule.enabled ? "" : " (off)"}</strong
                ><small
                  class="block truncate text-[9px] text-[#97a098]"
                  title={routerRule.domains.join(", ")}
                  >{routerRule.mode === "NotAllowed"
                    ? "Internet blocked"
                    : routerRule.mode || "Rule"} · {routerRule.domains.join(
                    ", ",
                  ) ||
                    (routerRule.mode === "NotAllowed"
                      ? "all sites"
                      : "no URLs")}</small
                ></span
              ><span class="truncate text-[10px] text-[#66746a]"
                >{routerRule.device_mac ?? "Unknown device"}{routerRule.schedule
                  ? ` · ${routerRule.schedule}`
                  : ""}</span
              ><button
                class="rounded border border-[#e9d4cc] px-2 py-2 text-[9px] font-bold text-[#a4533b] disabled:opacity-50"
                disabled={!routerLogin ||
                  deletingRouterRuleId === routerRule.inst_id}
                onclick={() => deleteRouterRule(routerRule)}
                >{deletingRouterRuleId === routerRule.inst_id
                  ? "Deleting..."
                  : "Delete from router"}</button
              >
            </div>{/each}
          {#if routerRulesError}<p class="py-4 text-xs text-[#9a6842]">
              {routerRulesError}
            </p>{:else if routerRules.length === 0}<p
              class="py-6 text-center text-xs text-[#8f9a91]"
            >
              {routerLogin
                ? routerRulesLoading
                  ? "Loading rules from the router..."
                  : "No parental-control rules found on the router."
                : "Sign in to the router to see its rules."}
            </p>{/if}
        </section>
      {:else}
        <div class="mb-5">
          <p class="eyebrow">DEVICE CONNECTION</p>
          <h1 class="font-display text-[29px] font-semibold">
            Router setup<span class="text-[#d7825d]">.</span>
          </h1>
          <p class="mt-2 text-xs text-[#748178]">
            Sign in to load devices and manage rules.
          </p>
        </div>
        <form
          class="mb-4 rounded-md border border-[#e4e9e2] bg-white p-4"
          onsubmit={testRouter}
        >
          <label
            for="router-address"
            class="mb-2 block text-[10px] font-bold text-[#526257]"
            >Router IPv4 address</label
          >
          <div class="flex flex-wrap gap-2">
            <input
              id="router-address"
              class="h-10 min-w-0 flex-1 rounded border border-[#dfe6df] px-3 text-xs text-[#33443a] outline-none focus:border-[#73a984]"
              bind:value={routerAddress}
              placeholder="192.168.1.1"
              required
            />
            <button
              type="submit"
              class="inline-flex h-10 items-center gap-2 rounded bg-[#245b43] px-4 text-[10px] font-bold text-white disabled:cursor-wait disabled:opacity-60"
              disabled={probingRouter}
            >
              {#if probingRouter}<Activity size={15} /> Testing...{:else}<Wifi
                  size={15}
                /> Test connection{/if}
            </button>
          </div>
          <p class="mt-2 text-[9px] text-[#88948a]">
            Optional read-only check of the local router page. This does not log
            in or change settings.
          </p>
        </form>
        {#if routerProbe}
          <div
            class="mb-4 flex items-center gap-2 rounded border border-[#d7e8d8] bg-[#edf5ec] p-3 text-[10px] text-[#34563d]"
          >
            <Check size={16} /> Router responded with HTTP {routerProbe.status}{#if routerProbe.title}
              · {routerProbe.title}{/if}. No settings were changed.
          </div>
        {/if}
        {#if routerProbeError}
          <div
            class="mb-4 flex items-start gap-2 rounded border border-[#eed9bd] bg-[#fcf8f0] p-3 text-[10px] text-[#755733]"
          >
            <ShieldAlert size={15} class="mt-0.5 shrink-0" />
            <span>{routerProbeError}</span>
          </div>
        {/if}
        {#if routerLogin}
          <div
            class="mb-4 flex flex-wrap items-center gap-3 rounded border border-[#d7e8d8] bg-[#edf5ec] p-3 text-[10px] text-[#34563d]"
          >
            <Check size={16} /> Router session active in memory{#if routerLogin.title}
              · {routerLogin.title}{/if}
            <button
              class="ml-auto rounded border border-[#c7ddc9] px-3 py-2 text-[10px] font-bold text-[#456a4a]"
              onclick={disconnectRouter}>Disconnect</button
            >
          </div>
        {:else}
          <form
            class="mb-4 grid grid-cols-2 gap-3 rounded-md border border-[#e4e9e2] bg-white p-4 max-[600px]:grid-cols-1"
            onsubmit={connectRouter}
          >
            <label
              class="flex flex-col gap-1.5 text-[10px] font-bold text-[#526257]"
              >Router username
              <input
                class="h-10 rounded border border-[#dfe6df] px-3 text-xs font-normal text-[#33443a] outline-none focus:border-[#73a984]"
                bind:value={routerUsername}
                autocomplete="username"
                required
              />
            </label>
            <label
              class="flex flex-col gap-1.5 text-[10px] font-bold text-[#526257]"
              >Router password
              <input
                class="h-10 rounded border border-[#dfe6df] px-3 text-xs font-normal text-[#33443a] outline-none focus:border-[#73a984]"
                type="password"
                bind:value={routerPassword}
                autocomplete="current-password"
                required
              />
            </label>
            <div
              class="col-span-2 flex flex-wrap items-center justify-between gap-3 max-[600px]:col-span-1"
            >
              <p class="text-[9px] text-[#88948a]">
                Used for this login only. The password is not saved; the session
                is held in memory.
              </p>
              <button
                type="submit"
                class="inline-flex h-9 items-center gap-2 rounded border border-[#dce5dc] bg-white px-3 text-[10px] font-bold text-[#456a4a] disabled:cursor-wait disabled:opacity-60"
                disabled={loggingIn}
              >
                {#if loggingIn}<Activity size={15} /> Signing in...{:else}<LockKeyhole
                    size={15}
                  /> Sign in to router{/if}
              </button>
            </div>
          </form>
        {/if}
        {#if routerLoginError}
          <div
            class="mb-4 flex items-start gap-2 rounded border border-[#eed9bd] bg-[#fcf8f0] p-3 text-[10px] text-[#755733]"
          >
            <ShieldAlert size={15} class="mt-0.5 shrink-0" />
            <span>{routerLoginError}</span>
          </div>
        {/if}
        <div class="grid grid-cols-2 gap-4 max-[850px]:grid-cols-1">
          <section class="rounded-md border border-[#e4e9e2] bg-white p-5">
            <div class="mb-5 flex items-start justify-between">
              <span
                class="grid size-12 place-items-center rounded-lg bg-[#e5f0e5] text-[#3a7150]"
                ><Router size={25} /></span
              >
              <span
                class="rounded-full border px-2 py-1 text-[9px] {routerLogin
                  ? 'border-[#d7e8d8] text-[#47805a]'
                  : routerProbe
                    ? 'border-[#e8e0c8] text-[#947641]'
                    : 'border-[#f0dfd5] text-[#a16b4f]'}"
                >{routerLogin
                  ? "Connected"
                  : routerProbe
                    ? "Reachable"
                    : "Not connected"}</span
              >
            </div>
            <p class="eyebrow">DETECTED FIRMWARE</p>
            <h2 class="font-display text-xl font-semibold">
              ZTE F670L <span class="text-sm text-[#77907c]">V9.0</span>
            </h2>
            <p class="mt-1 text-[10px] text-[#88948a]">Build V9.0.10P18N3D</p>
            <div
              class="mt-4 divide-y divide-[#edf0ec] border-y border-[#edf0ec]"
            >
              <div class="flex justify-between py-3 text-[10px]">
                <span class="text-[#87938a]">Admin address</span><strong
                  >{routerAddress.trim()}</strong
                >
              </div>
              <div class="flex justify-between py-3 text-[10px]">
                <span class="text-[#87938a]">Per-device URL action</span><strong
                  class="flex items-center gap-1 text-[#47805a]"
                  ><Check size={13} /> Confirmed</strong
                >
              </div>
              <div class="flex justify-between py-3 text-[10px]">
                <span class="text-[#87938a]">Rule application</span><strong
                  class="text-[#aa7a45]">Manual confirmation</strong
                >
              </div>
            </div>
            <button
              class="mt-4 inline-flex h-9 w-full items-center justify-center gap-2 rounded bg-[#245b43] text-[11px] font-bold text-white"
              onclick={openRouter}
              ><ExternalLink size={15} /> Open router admin</button
            >
          </section>
          <section class="rounded-md border border-[#e4e9e2] bg-white p-5">
            <p class="eyebrow">INTEGRATION STATUS</p>
            <h2 class="font-display text-lg font-semibold">
              Router setup status
            </h2>
            <p class="my-3 text-[10px] leading-relaxed text-[#77847a]">
              Sign in with the router account, then apply each rule separately.
              Device names remain local labels; use the MAC address from the
              router.
            </p>
            <div class="space-y-3 border-t border-[#edf0ec] pt-3">
              <p class="flex items-center gap-2 text-[10px]">
                <span
                  class="grid size-5 place-items-center rounded-full bg-[#e9f3e8] text-[#4e865b]"
                  ><Check size={12} /></span
                > Firmware and per-device URL action identified
              </p>
              <p
                class="flex items-center gap-2 text-[10px] {routerLogin
                  ? ''
                  : 'text-[#7c887f]'}"
              >
                <span
                  class="grid size-5 place-items-center rounded-full {routerLogin
                    ? 'bg-[#e9f3e8] text-[#4e865b]'
                    : 'border border-[#dbe3da]'}"
                  >{#if routerLogin}<Check size={12} />{:else}2{/if}</span
                >
                {routerLogin
                  ? "Signed in to the router"
                  : "Sign in to the router"}
              </p>
            </div>
            <div
              class="mt-4 flex items-center gap-2 rounded bg-[#fbf5e9] p-2.5 text-[9px] text-[#95713e]"
            >
              <ShieldAlert size={15} />
              {routerLogin
                ? "Signed in. Router settings change only when you confirm an Apply or Delete."
                : "Not signed in. The app makes no router changes until you sign in and confirm."}
            </div>
          </section>
        </div>
      {/if}
      <footer class="mt-6 flex justify-between text-[9px] text-[#a0aaa2]">
        <span class="flex items-center gap-1"
          ><Command size={12} /> ROUTER WARDEN · LOCAL CONTROL</span
        ><span>No cloud sync</span>
      </footer>
    </div>
  </main>
</div>

{#if modalOpen}
  <div
    class="fixed inset-0 z-10 grid place-items-center bg-[#10221980] p-4 backdrop-blur-sm"
    role="presentation"
    onclick={(event) =>
      event.target === event.currentTarget && (modalOpen = false)}
  >
    <div
      class="w-full max-w-[420px] rounded-lg border border-[#e2e8e1] bg-white p-5 shadow-2xl"
      role="dialog"
      aria-modal="true"
      aria-labelledby="rule-title"
      tabindex="-1"
    >
      <div class="mb-5 flex items-center justify-between">
        <div class="flex items-center gap-3">
          <span
            class="grid size-9 place-items-center rounded bg-[#e6f1e7] text-[#39704d]"
            ><ShieldCheck size={19} /></span
          >
          <div>
            <p class="eyebrow">NEW ACCESS RULE</p>
            <h2 id="rule-title" class="font-display text-lg font-semibold">
              Block a website
            </h2>
          </div>
        </div>
        <button
          class="p-1 text-[#66736b]"
          aria-label="Close"
          onclick={() => (modalOpen = false)}><X size={18} /></button
        >
      </div>
      <form onsubmit={addRule}>
        <label
          class="mb-4 flex items-start gap-2 rounded border border-[#ecd9d2] bg-[#fbf3f0] p-2.5 text-[10px] text-[#8a4a38]"
          ><input
            type="checkbox"
            class="mt-0.5"
            bind:checked={blockAllInternet}
          /><span
            ><strong class="block text-[10px]"
              >Block all internet for this device</strong
            >The device is offline until you delete the rule. Website list not
            needed.</span
          ></label
        >
        {#if !blockAllInternet}
          <div class="mb-1.5 flex items-center justify-between gap-2">
            <label
              for="domain"
              class="block text-[10px] font-bold text-[#526257]"
              >Website domains</label
            >
            <button
              type="button"
              class="text-[9px] font-bold text-[#3c7652]"
              onclick={() => (domain = YOUTUBE_APP_DOMAINS.join("\n"))}
              >YouTube app preset</button
            >
          </div>
          <div
            class="mb-1 flex items-start gap-2 rounded border border-[#dfe6df] px-2.5 py-2 text-[#859289]"
          >
            <Globe2 size={16} class="mt-1 shrink-0" /><textarea
              id="domain"
              class="min-h-20 w-full resize-y border-0 bg-transparent text-[11px] text-[#33443a] outline-none"
              bind:value={domain}
              placeholder="example.com&#10;video.example.com"
              rows="4"
              autocomplete="off"
              required></textarea>
          </div>
          <small class="mb-4 block text-[9px] text-[#97a198]"
            >Add 1–5 hostnames, one per line. The preset includes common YouTube
            app, API, video, and image hosts.</small
          >
        {/if}
        <label
          for="device-label"
          class="mb-1.5 block text-[10px] font-bold text-[#526257]"
          >Device label</label
        >
        <input
          id="device-label"
          class="mb-4 h-10 rounded border border-[#dfe6df] px-3 text-[11px] text-[#33443a] outline-none"
          bind:value={deviceLabel}
          placeholder="e.g. child's phone"
          autocomplete="off"
          required
        />
        <label
          for="device-mac"
          class="mb-1.5 block text-[10px] font-bold text-[#526257]"
          >Device MAC address</label
        >
        <input
          id="device-mac"
          class="mb-4 h-10 rounded border border-[#dfe6df] px-3 font-mono text-[11px] text-[#33443a] outline-none"
          bind:value={deviceMac}
          placeholder="01:23:45:67:89:AB"
          maxlength="17"
          autocomplete="off"
          required
        />
        <fieldset class="mb-4 rounded border border-[#dfe6df] p-2.5">
          <legend class="px-1 text-[10px] font-bold text-[#526257]"
            >Schedule</legend
          >
          <div class="mb-2 flex gap-4 text-[10px] text-[#526257]">
            <label class="flex items-center gap-1.5"
              ><input
                type="radio"
                name="schedule-mode"
                checked={!scheduleCustom}
                onchange={() => (scheduleCustom = false)}
              /> All day, every day</label
            >
            <label class="flex items-center gap-1.5"
              ><input
                type="radio"
                name="schedule-mode"
                checked={scheduleCustom}
                onchange={() => (scheduleCustom = true)}
              /> Specific days and times</label
            >
          </div>
          {#if scheduleCustom}
            <div class="mb-2 flex flex-wrap gap-1.5">
              {#each DAY_NAMES as dayName, dayIndex}<label
                  class="cursor-pointer rounded border px-2 py-1 text-[10px] font-semibold {scheduleDays.includes(
                    dayIndex,
                  )
                    ? 'border-[#245b43] bg-[#245b43] text-white'
                    : 'border-[#dfe6df] text-[#637168]'}"
                  ><input
                    type="checkbox"
                    class="sr-only"
                    checked={scheduleDays.includes(dayIndex)}
                    onchange={() =>
                      (scheduleDays = scheduleDays.includes(dayIndex)
                        ? scheduleDays.filter((day) => day !== dayIndex)
                        : [...scheduleDays, dayIndex])}
                  />{dayName}</label
                >{/each}
            </div>
            <div class="flex items-center gap-2 text-[10px] text-[#526257]">
              <label for="schedule-start">From</label>
              <input
                id="schedule-start"
                type="time"
                class="h-8 rounded border border-[#dfe6df] px-2 text-[11px]"
                bind:value={scheduleStart}
              />
              <label for="schedule-end">to</label>
              <input
                id="schedule-end"
                type="time"
                class="h-8 rounded border border-[#dfe6df] px-2 text-[11px]"
                bind:value={scheduleEnd}
              />
            </div>
            <small class="mt-1.5 block text-[9px] text-[#97a198]"
              >The end must be later than the start on the same day. For
              overnight blocking, make two rules.</small
            >
          {/if}
        </fieldset>
        <div
          class="flex gap-2 rounded bg-[#f8f5ed] p-2.5 text-[9px] leading-relaxed text-[#8b7857]"
        >
          <LockKeyhole size={14} class="mt-0.5 shrink-0" /><span
            >Router application creates one profile with this schedule. Review
            the device MAC carefully before applying.</span
          >
        </div>
        <div class="mt-5 flex justify-end gap-2">
          <button
            type="button"
            class="h-9 rounded border border-[#dfe5de] px-3 text-[10px] font-semibold text-[#637168]"
            onclick={() => (modalOpen = false)}>Cancel</button
          ><button
            type="submit"
            class="inline-flex h-9 items-center gap-1.5 rounded bg-[#245b43] px-3 text-[10px] font-bold text-white"
            ><Plus size={15} /> Save rule</button
          >
        </div>
      </form>
    </div>
  </div>
{/if}
{#if notice}<div
    class="fixed bottom-5 right-5 z-20 flex max-w-[min(400px,calc(100vw-30px))] items-center gap-2 rounded border border-[#d9e6d9] bg-white px-3.5 py-3 text-[10px] text-[#4a614f] shadow-lg"
  >
    <ShieldAlert size={15} />
    {notice}
  </div>{/if}

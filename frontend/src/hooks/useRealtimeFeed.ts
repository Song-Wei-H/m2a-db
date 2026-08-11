import { useEffect, useState } from "react";

export function useRealtimeFeed(targetId: number) {
  const [messages, setMessages] = useState<string[]>([]);
  const [status, setStatus] = useState<"disabled" | "connecting" | "connected" | "closed">("disabled");

  useEffect(() => {
    const endpoint = localStorage.getItem("m2a.wsEndpoint");
    if (!endpoint || targetId <= 0) {
      setStatus("disabled");
      return;
    }

    const url = endpoint.replace("{targetId}", String(targetId));
    setStatus("connecting");
    const socket = new WebSocket(url);
    socket.onopen = () => setStatus("connected");
    socket.onmessage = (event) => setMessages((current) => [String(event.data), ...current].slice(0, 100));
    socket.onclose = () => setStatus("closed");
    socket.onerror = () => setStatus("closed");
    return () => socket.close();
  }, [targetId]);

  return { messages, status };
}

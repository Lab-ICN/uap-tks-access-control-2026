const $ = (id) => document.getElementById(id);
let current = -1;
const ctfConfig = JSON.parse(document.getElementById("ctf-config").textContent);

async function api(url, body) {
  const response = await fetch(url, {
    method: body === undefined ? "GET" : "POST",
    headers: {
      "Content-Type": "application/json",
      "X-CSRF-Token": ctfConfig.csrf,
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const data = await response.json();
  if (!response.ok) {
    throw Error(data.error || "Request failed");
  }
  return data;
}

function append(command, output) {
  const block = document.createElement("div");
  block.className = "term-block";

  if (command) {
    const line = document.createElement("div");
    line.className = "prompt";
    line.textContent = `analyst@robintech:~$ ${command}`;
    block.appendChild(line);
  }

  const pre = document.createElement("pre");
  pre.textContent = output;
  block.appendChild(pre);
  $("termOutput").appendChild(block);
  $("termOutput").scrollTop = $("termOutput").scrollHeight;
}

async function load() {
  try {
    const data = await api("/api/state");
    $("count").textContent = `${data.progress}/${data.total}`;
    $("percent").textContent = `${Math.round((100 * data.progress) / data.total)}%`;
    $("bar").style.width = `${(100 * data.progress) / data.total}%`;

    if (data.done) {
      $("mainContent").hidden = true;
      $("success").hidden = false;
      $("flag").textContent = data.flag;
      return;
    }

    if (current !== data.progress) {
      current = data.progress;
      $("caseNumber").textContent =
        `CASE ${String(current + 1).padStart(2, "0")} / ${data.total}`;

      for (const key of ["title", "story", "question", "hint", "category"]) {
        $(key).textContent = data.challenge[key];
      }
      $("answer").value = "";
      $("feedback").textContent = "";
      $("feedback").className = "feedback";
      $("termOutput").textContent = "";
      append(
        "",
        "RobinTech Forensic Console v2.0\n" +
          "Lingkungan evidence read-only. Tidak ada akses shell asli.\n" +
          "Ketik 'help' untuk melihat supported commands.\n" +
          "Mulai dengan menginvestigasi home directory Anda.",
      );
      document.querySelector("details").open = false;
    }
  } catch (error) {
    $("feedback").textContent = error.message;
  }
}

$("terminalForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const command = $("command").value.trim();
  if (!command) return;

  $("command").value = "";
  try {
    const data = await api("/api/terminal", { command });
    if (data.clear) {
      $("termOutput").textContent = "";
    } else {
      append(command, data.output);
    }
  } catch (error) {
    append(command, error.message);
  }
});

$("answerForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const answer = $("answer").value.trim();
  if (!answer) return;

  const button = event.target.querySelector("button");
  button.disabled = true;
  try {
    const data = await api("/api/answer", { answer });
    $("feedback").textContent = data.message;
    $("feedback").className = `feedback ${data.correct ? "ok" : "bad"}`;
    if (data.correct) {
      await new Promise((resolve) => setTimeout(resolve, 600));
      await load();
    }
  } catch (error) {
    $("feedback").textContent = error.message;
  } finally {
    button.disabled = false;
  }
});

$("copyFlag").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText($("flag").textContent);
    $("copyFlag").textContent = "TERSALIN!";
  } catch {
    $("copyFlag").textContent = "PILIH FLAG UNTUK DISALIN";
  }
});

const theme = localStorage.getItem("robintech-theme") || "dark";
if (theme === "light") document.body.classList.add("light");
$("themeToggle").textContent = theme === "light" ? "☾" : "☀";
$("themeToggle").addEventListener("click", () => {
  document.body.classList.toggle("light");
  const nextTheme = document.body.classList.contains("light") ? "light" : "dark";
  localStorage.setItem("robintech-theme", nextTheme);
  $("themeToggle").textContent = nextTheme === "light" ? "☾" : "☀";
});

load();

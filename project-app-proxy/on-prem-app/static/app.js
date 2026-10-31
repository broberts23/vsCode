const output = document.getElementById("host-output");
const button = document.getElementById("load-host");

button.addEventListener("click", async () => {
  output.textContent = "Loading…";
  try {
    const response = await fetch("/api/host");
    const body = await response.text();
    if (!response.ok) {
      output.textContent = `HTTP ${response.status}\n${body}`;
      return;
    }
    output.textContent = JSON.stringify(JSON.parse(body), null, 2);
  } catch (error) {
    output.textContent = String(error);
  }
});

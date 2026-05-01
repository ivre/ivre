import { Button } from "@/components/ui/button";

function App() {
  return (
    <main className="flex min-h-screen flex-col items-center justify-center gap-6 bg-background p-8 text-foreground">
      <h1 className="text-4xl font-semibold tracking-tight">
        IVRE web-ui workspace
      </h1>
      <p className="max-w-prose text-center text-muted-foreground">
        This is a scaffold for the new IVRE web UI. Real pages will land in
        follow-up changes.
      </p>
      <Button data-testid="ping">Ping</Button>
    </main>
  );
}

export default App;

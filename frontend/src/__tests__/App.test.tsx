import { render, screen } from "@testing-library/react";

import App from "../App";

test("renders the ClickSafe dashboard", () => {
  render(<App />);

  expect(screen.getByText("ClickSafe")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: /analyze url/i })).toBeInTheDocument();
});


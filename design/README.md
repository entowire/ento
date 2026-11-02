# Design references

`dashboard/` is the approved mockup of the admin dashboard (2026-11-01), the reference for
`internal/control/ui`: a canvas of static pages (`project/*.dc.html`, one per screen; `canvas.json`
lays them out). Its `/_blob/...` font addresses are the canvas's own copies of the embedded fonts.
Screens it shows that the dashboard does not have yet (activity, seats, passkeys) wait for the API
they need.

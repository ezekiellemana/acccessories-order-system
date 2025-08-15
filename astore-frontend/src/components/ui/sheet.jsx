import React, { createContext, useContext, useState } from 'react';

const SheetContext = createContext({
  open: false,
  setOpen: () => {}
});

export function Sheet({ children }) {
  const [open, setOpen] = useState(false);
  return (
    <SheetContext.Provider value={{ open, setOpen }}>
      {children}
    </SheetContext.Provider>
  );
}

export function SheetTrigger({ asChild, children }) {
  const { setOpen } = useContext(SheetContext);
  // if asChild, clone the child and inject onClick
  const child = React.Children.only(children);
  return React.cloneElement(child, {
    onClick: () => setOpen(true),
  });
}

export function SheetContent({ side = 'right', className = '', children }) {
  const { open, setOpen } = useContext(SheetContext);
  if (!open) return null;
  // basic full-screen overlay
  return (
    <div
      className={`fixed inset-0 flex ${side === 'right' ? 'justify-end' : ''} ${className}`}
      style={{ background: 'rgba(0,0,0,0.5)' }}
    >
      <div className="bg-white h-full w-60">
        {children}
      </div>
    </div>
  );
}

export function SheetClose({ asChild, children }) {
  const { setOpen } = useContext(SheetContext);
  const child = React.Children.only(children);
  return React.cloneElement(child, {
    onClick: () => setOpen(false),
  });
}

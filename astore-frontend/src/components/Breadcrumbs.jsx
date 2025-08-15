import React from 'react';
import { Link, useLocation } from 'react-router-dom';

export default function Breadcrumbs() {
  const location = useLocation();
  const segments = location.pathname.split('/').filter(Boolean);

  const crumbs = segments.map((segment, idx) => {
    const path = '/' + segments.slice(0, idx + 1).join('/');
    const label = segment
      .replace(/[-_]/g, ' ')
      .replace(/\b\w/g, (c) => c.toUpperCase());
    return { label, path };
  });

  return (
    <nav aria-label="Breadcrumb">
      <ol className="flex space-x-2 text-sm text-neutral-600">
        <li>
          <Link to="/admin" className="px-2 py-1 bg-neutral-200 rounded-full hover:bg-neutral-300">
            Admin
          </Link>
        </li>
        {crumbs.slice(1).map((crumb, i) => (
          <li key={crumb.path} className="flex items-center">
            <span className="mx-2 text-neutral-500">/</span>
            {i < crumbs.slice(1).length - 1 ? (
              <Link
                to={crumb.path}
                className="px-2 py-1 bg-neutral-200 rounded-full hover:bg-neutral-300"
              >
                {crumb.label}
              </Link>
            ) : (
              <span className="px-2 py-1 bg-primary-100 text-primary-700 rounded-full font-medium">
                {crumb.label}
              </span>
            )}
          </li>
        ))}
      </ol>
    </nav>
  );
}

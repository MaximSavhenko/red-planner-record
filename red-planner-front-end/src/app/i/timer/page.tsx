import type { Metadata } from 'next'

import { NO_INDEX_PAGE } from '@/constants/seo.constants'

export const metadata: Metadata = {
  title: 'PageTitle',
  ...NO_INDEX_PAGE
}

export default function page() {
  return <div>page</div>;
}
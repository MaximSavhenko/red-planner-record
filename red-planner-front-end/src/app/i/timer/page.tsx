import type { Metadata } from 'next'

import { NO_INDEX_PAGE } from '@/constants/seo.constants'
import { Heading } from '@/components/ui/Heading';
import { Pomodoro } from './Pomodoro';

export const metadata: Metadata = {
  title: 'PageTitle',
  ...NO_INDEX_PAGE
}

export default function page() {
  return <div>
    <Heading title='Pomodoro timer' />
    <Pomodoro />
  </div>;
}
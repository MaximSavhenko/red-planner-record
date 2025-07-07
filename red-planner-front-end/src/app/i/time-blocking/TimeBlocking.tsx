'use client'

import { FormProvider, useForm } from 'react-hook-form'

import { TypeTimeBlockFormState } from '@/types/time-block.types'

import { TimeBLockingList } from './TimeBLockingList'
import { TimeBlockingForm } from './form/TimeBlockingForm'

export function TimeBlocking() {
	const methods = useForm<TypeTimeBlockFormState>()

	return (
		<FormProvider {...methods}>
			<div className='grid grid-cols-2 gap-12'>
				<TimeBLockingList />
				<TimeBlockingForm />
			</div>
		</FormProvider>
	)
}

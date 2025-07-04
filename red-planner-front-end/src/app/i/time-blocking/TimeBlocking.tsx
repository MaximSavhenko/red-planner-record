'use client'

import { FormProvider, useForm } from 'react-hook-form'

import { TypeTimeBlockFormState } from '@/types/time-block.types'

import { TimeBlockingForm } from './form/TimeBlockingForm'

export function TimeBlocking() {
	const methods = useForm<TypeTimeBlockFormState>()

	return (
		<FormProvider {...methods}>
			<div className='grid grid-color-2 gap-12'>
				<TimeBlockingForm />
			</div>
		</FormProvider>
	)
}
